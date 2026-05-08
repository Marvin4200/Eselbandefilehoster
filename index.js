'use strict';
require('dotenv').config();

const express = require('express');
const compression = require('compression');
const session = require('express-session');
const Database = require('better-sqlite3');
const busboy = require('busboy');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// ── Config ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3011;
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'https://files.eselbande.com/auth/callback';
const SESSION_SECRET = process.env.SESSION_SECRET || 'changeme';
if (SESSION_SECRET === 'changeme' && process.env.NODE_ENV === 'production') {
    throw new Error('SESSION_SECRET must be set in production. Refusing to start.');
}
const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500 MB
const MAX_FILES_PER_USER = 200;
const MAX_TOTAL_BYTES_PER_USER = 2 * 1024 * 1024 * 1024; // 2 GB per user
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// MIME types and extensions that must never be served inline (XSS risk)
const BLOCKED_MIME_TYPES = new Set([
    'text/html', 'application/xhtml+xml', 'text/xml', 'application/xml',
    'image/svg+xml', 'application/javascript', 'text/javascript',
    'application/x-javascript', 'text/vbscript', 'application/x-httpd-php',
]);
const BLOCKED_EXTENSIONS = new Set([
    '.html', '.htm', '.xhtml', '.svg', '.xml', '.js', '.mjs', '.cjs',
    '.php', '.php3', '.php4', '.php5', '.phtml', '.py', '.rb', '.sh',
    '.bash', '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.jar',
]);

// ── Storage dirs ─────────────────────────────────────────────────────────────
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ── Database ──────────────────────────────────────────────────────────────────
const db = new Database(path.join(dataDir, 'files.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    discord_id TEXT    UNIQUE NOT NULL,
    username   TEXT    NOT NULL,
    avatar     TEXT,
    created_at TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS files (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id      TEXT    UNIQUE NOT NULL,
    orig_name    TEXT    NOT NULL,
    stored_name  TEXT    NOT NULL,
    mime_type    TEXT    NOT NULL,
    size         INTEGER NOT NULL,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    downloads    INTEGER DEFAULT 0,
    created_at   TEXT    DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_files_user   ON files(user_id);
  CREATE INDEX IF NOT EXISTS idx_files_fileid ON files(file_id);
`);

// ── App ───────────────────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);

// Security headers (no external dependency)
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
        res.setHeader('Content-Security-Policy',
            "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://cdn.discordapp.com; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'");
    next();
});
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000,
    },
}));
app.use(express.static(path.join(__dirname, 'public')));

// ── Helpers ───────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    next();
}

// ── Rate limiting (in-memory, no external dependency) ─────────────────────────
const _rlStore = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of _rlStore) if (now > v.reset + 60_000) _rlStore.delete(k);
}, 5 * 60_000);
function createRateLimiter(max, windowMs) {
    return (req, res, next) => {
        const key = req.ip;
        const now = Date.now();
        const e = _rlStore.get(key) || { count: 0, reset: now + windowMs };
        if (now > e.reset) { e.count = 0; e.reset = now + windowMs; }
        if (++e.count > max) {
            res.setHeader('Retry-After', Math.ceil((e.reset - now) / 1000));
            return res.status(429).json({ error: 'Zu viele Anfragen. Bitte warte kurz.' });
        }
        _rlStore.set(key, e);
        next();
    };
}
const authLimiter = createRateLimiter(20, 60_000);   // 20 auth attempts / min
const uploadLimiter = createRateLimiter(30, 60_000); // 30 uploads / min

function sanitizeFilename(name) {
    return path.basename(String(name || 'file'))
        .replace(/[^\w.\-]/g, '_')
        .slice(0, 200);
}

function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
    return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

// ── Auth ──────────────────────────────────────────────────────────────────────
app.get('/auth/login', (req, res) => {
    const params = new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        redirect_uri: DISCORD_REDIRECT_URI,
        response_type: 'code',
        scope: 'identify',
    });
    res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

app.get('/auth/callback', authLimiter, async (req, res) => {
    const { code } = req.query;
    if (!code || typeof code !== 'string') return res.redirect('/?error=missing_code');

    try {
        const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code,
                redirect_uri: DISCORD_REDIRECT_URI,
            }),
        });
        if (!tokenRes.ok) throw new Error(`Token exchange: ${tokenRes.status}`);
        const tokenData = await tokenRes.json();

        const userRes = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` },
        });
        if (!userRes.ok) throw new Error(`Discord user: ${userRes.status}`);
        const du = await userRes.json();

        db.prepare(`
            INSERT INTO users (discord_id, username, avatar) VALUES (?, ?, ?)
            ON CONFLICT(discord_id) DO UPDATE SET username = excluded.username, avatar = excluded.avatar
        `).run(String(du.id), String(du.username), du.avatar ? String(du.avatar) : null);

        const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(String(du.id));
        req.session.user = { id: user.id, discordId: du.id, username: du.username, avatar: du.avatar };
        res.redirect('/');
    } catch (err) {
        console.error('[AUTH]', err.message);
        res.redirect('/?error=auth_failed');
    }
});

app.get('/auth/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

// ── API ───────────────────────────────────────────────────────────────────────
app.get('/api/me', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    const userId = req.session.user.id;
    const { total_bytes } = db.prepare(
        'SELECT COALESCE(SUM(size), 0) AS total_bytes FROM files WHERE user_id = ?'
    ).get(userId);
    res.json({ ...req.session.user, usedBytes: total_bytes, quotaBytes: MAX_TOTAL_BYTES_PER_USER });
});

app.get('/api/files', requireAuth, (req, res) => {
    const files = db.prepare(
        'SELECT id, file_id, orig_name, mime_type, size, downloads, created_at FROM files WHERE user_id = ? ORDER BY created_at DESC'
    ).all(req.session.user.id);
    res.json(files);
});

// Upload via busboy — streams directly to disk, no temp file in memory
app.post('/api/upload', uploadLimiter, requireAuth, (req, res) => {
    const userId = req.session.user.id;

    const count = db.prepare('SELECT COUNT(*) as c FROM files WHERE user_id = ?').get(userId);
    if (count.c >= MAX_FILES_PER_USER) {
        return res.status(429).json({ error: `Datei-Limit erreicht (${MAX_FILES_PER_USER})` });
    }

    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    if (contentLength > MAX_FILE_SIZE + 1024) {
        return res.status(413).json({ error: 'Datei zu groß (max 500 MB)' });
        // Check per-user storage quota (2 GB)
        const { total_bytes } = db.prepare(
            'SELECT COALESCE(SUM(size), 0) AS total_bytes FROM files WHERE user_id = ?'
        ).get(userId);
        if (total_bytes + contentLength > MAX_TOTAL_BYTES_PER_USER) {
            return res.status(413).json({ error: 'Speicherlimit erreicht (max. 2 GB pro Nutzer)' });
        }

    }

    let bb;
    try {
        bb = busboy({ headers: req.headers, limits: { files: 1, fileSize: MAX_FILE_SIZE } });
    } catch {
        return res.status(400).json({ error: 'Ungültige Anfrage' });
    }

    let responded = false;

    bb.on('file', (fieldname, file, info) => {
        const { filename, mimeType } = info;
        const safeName = sanitizeFilename(filename || 'upload');
        const ext = path.extname(safeName).toLowerCase();

        // Block dangerous file types that could lead to XSS or RCE
        if (BLOCKED_EXTENSIONS.has(ext) || BLOCKED_MIME_TYPES.has((mimeType || '').toLowerCase().split(';')[0].trim())) {
            file.resume(); // drain the stream
            if (!responded) {
                responded = true;
                return res.status(415).json({ error: 'Dieser Dateityp ist nicht erlaubt' });
            }
            return;
        }

        const fileId = crypto.randomBytes(8).toString('hex');
        const storedName = `${fileId}${ext}`;
        const destPath = path.join(UPLOAD_DIR, storedName);
        const writeStream = fs.createWriteStream(destPath);

        let bytesWritten = 0;
        let limitHit = false;

        file.on('data', chunk => { bytesWritten += chunk.length; });
        file.on('limit', () => {
            limitHit = true;
            writeStream.destroy();
            try { fs.unlinkSync(destPath); } catch { }
            if (!responded) {
                responded = true;
                res.status(413).json({ error: 'Datei zu groß (max 500 MB)' });
            }
        });

        file.pipe(writeStream);

        writeStream.on('finish', () => {
            if (limitHit || responded) return;

            try {
                db.prepare(`
                    INSERT INTO files (file_id, orig_name, stored_name, mime_type, size, user_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                `).run(fileId, safeName, storedName, String(mimeType || 'application/octet-stream'), bytesWritten, userId);

                responded = true;
                res.json({
                    fileId,
                    url: `https://files.eselbande.com/f/${fileId}/${encodeURIComponent(safeName)}`,
                    name: safeName,
                    size: bytesWritten,
                });
            } catch (err) {
                console.error('[UPLOAD] DB error:', err);
                try { fs.unlinkSync(destPath); } catch { }
                if (!responded) { responded = true; res.status(500).json({ error: 'Interner Fehler' }); }
            }
        });

        writeStream.on('error', () => {
            try { fs.unlinkSync(destPath); } catch { }
            if (!responded) { responded = true; res.status(500).json({ error: 'Interner Fehler beim Schreiben' }); }
        });
    });

    bb.on('error', () => {
        if (!responded) { responded = true; res.status(400).json({ error: 'Upload-Fehler' }); }
    });

    req.pipe(bb);
});

app.delete('/api/files/:id', requireAuth, (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id) || id < 1) return res.status(400).json({ error: 'Ungültige ID' });

    const file = db.prepare('SELECT * FROM files WHERE id = ? AND user_id = ?').get(id, req.session.user.id);
    if (!file) return res.status(404).json({ error: 'Datei nicht gefunden' });

    try { fs.unlinkSync(path.join(UPLOAD_DIR, file.stored_name)); } catch { }
    db.prepare('DELETE FROM files WHERE id = ?').run(id);
    res.json({ success: true });
});

// ── File download/view ────────────────────────────────────────────────────────
app.get('/f/:fileId/:filename?', (req, res) => {
    const { fileId } = req.params;
    if (!/^[a-f0-9]{16}$/.test(fileId)) return res.status(404).send('Datei nicht gefunden');

    const file = db.prepare('SELECT * FROM files WHERE file_id = ?').get(fileId);
    if (!file) return res.status(404).send('Datei nicht gefunden');

    const filePath = path.join(UPLOAD_DIR, file.stored_name);
    if (!fs.existsSync(filePath)) return res.status(404).send('Datei nicht gefunden');

    db.prepare('UPDATE files SET downloads = downloads + 1 WHERE id = ?').run(file.id);

    // Inline display for images/videos/audio; download otherwise.
    // Never serve HTML/JS/SVG/XML inline (XSS risk).
    const safeMime = file.mime_type.toLowerCase().split(';')[0].trim();
    const safeExt = path.extname(file.stored_name).toLowerCase();
    const isDangerous = BLOCKED_MIME_TYPES.has(safeMime) || BLOCKED_EXTENSIONS.has(safeExt);
    const inlineMimes = /^(image|video|audio)\//;
    const disposition = (!isDangerous && inlineMimes.test(safeMime)) ? 'inline' : 'attachment';

    res.setHeader('Content-Type', file.mime_type);
    res.setHeader('Content-Disposition', `${disposition}; filename="${file.orig_name}"`);
    res.setHeader('Content-Length', file.size);
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    fs.createReadStream(filePath).pipe(res);
});

// ── Health ───────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', service: 'filehoster', uptime: process.uptime() }));

// ── Start ─────────────────────────────────────────────────────────────────────
// ── 404 & Error handlers ─────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Nicht gefunden', path: req.path }));
app.use((err, req, res, next) => {
    console.error('[ERROR]', err.message);
    res.status(500).json({ error: 'Interner Serverfehler' });
});

app.listen(PORT, () => console.log(`[files.eselbande.com] Running on port ${PORT}`));
