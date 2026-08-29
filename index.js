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


// ── Admin-Log ─────────────────────────────────────────────────────────────────
// Faengt praktisch alles ab: nicht nur Abstuerze, sondern auch die vielen
// try/catch-Stellen im Code, die einen Fehler bisher nur lokal geloggt haben.
// console.error/console.warn werden global umgeleitet - jeder Aufruf,
// egal wo im Prozess, geht jetzt zusaetzlich an admin.eselbande.com.
const ADMIN_LOG_URL = (process.env.ADMIN_LOG_URL || '').replace(/\/+$/, '');
const LOG_INGEST_TOKEN = process.env.LOG_INGEST_TOKEN || '';

// Ratenbegrenzung: waehrend eines Fehlersturms (z.B. eine haengende
// Verbindung, die minuetlich denselben Fehler wirft) soll admin-dashboard
// nicht mit hunderten Anfragen pro Minute geflutet werden. Token-Bucket:
// 30 Log-Sendungen sofort verfuegbar, danach eine neue alle 2 Sekunden.
let _logTokens = 30;
setInterval(() => { _logTokens = Math.min(30, _logTokens + 1); }, 2000);
let _logSuppressedSince = 0;

async function logAdmin(type, title, description, color, fields) {
    if (!ADMIN_LOG_URL || !LOG_INGEST_TOKEN) return;
    if (_logTokens <= 0) { _logSuppressedSince++; return; }
    _logTokens--;
    if (_logSuppressedSince > 0) {
        const n = _logSuppressedSince;
        _logSuppressedSince = 0;
        logAdmin('SYSTEM', '\u{1F507} Logs gedrosselt', `${n} weitere Meldungen in kurzer Zeit wurden nicht einzeln gesendet (Ratenbegrenzung).`, 0xF59E0B);
    }
    try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        await fetch(`${ADMIN_LOG_URL}/api/logs/ingest`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Log-Token': LOG_INGEST_TOKEN },
            body: JSON.stringify({ source: 'filehoster', type, title, description, color, fields }),
            signal: controller.signal,
        }).catch(() => {});
        clearTimeout(timer);
    } catch { /* ein Log-Sendefehler darf den Dienst selbst nie beeintraechtigen */ }
}

function _fmtConsoleArgs(args) {
    return args.map(a => {
        if (a instanceof Error) return a.stack || a.message;
        if (a && typeof a === 'object') { try { return JSON.stringify(a); } catch { return String(a); } }
        return String(a);
    }).join(' ').slice(0, 4000);
}

const _origConsoleError = console.error.bind(console);
const _origConsoleWarn = console.warn.bind(console);
console.error = (...args) => {
    _origConsoleError(...args);
    logAdmin('ERRORS', '\u{26A0}\u{FE0F} Fehler', _fmtConsoleArgs(args), 0xED4245);
};
console.warn = (...args) => {
    _origConsoleWarn(...args);
    logAdmin('WARNINGS', '\u{26A0}\u{FE0F} Warnung', _fmtConsoleArgs(args), 0xF59E0B);
};

process.on('uncaughtException', (err) => {
    console.error('[uncaughtException]', err);
});
process.on('unhandledRejection', (reason) => {
    console.error('[unhandledRejection]', reason);
});
logAdmin('SYSTEM', '\u{1F680} filehoster gestartet', `Prozess laeuft, PID ${process.pid}.`, 0x57F287);



// ── Config ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3011;
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'https://files.eselbande.com/auth/callback';
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || 'https://files.eselbande.com').replace(/\/+$/, '');
const SESSION_SECRET = process.env.SESSION_SECRET || 'changeme';
if (SESSION_SECRET === 'changeme' && process.env.NODE_ENV === 'production') {
    throw new Error('SESSION_SECRET must be set in production. Refusing to start.');
}
const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500 MB

// ── Passwort-Hashing ──────────────────────────────────────────────────────────
function hashPassword(pw) {
    return crypto.createHash('sha256').update(String(pw)).digest('hex');
}

// ── Ablaufdatum-Hilfsfunktionen ───────────────────────────────────────────────
const EXPIRY_MAP = { '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800, '30d': 2592000 };
function expiresAt(key) {
    const secs = EXPIRY_MAP[key];
    if (!secs) return null;
    return new Date(Date.now() + secs * 1000).toISOString();
}
function isExpired(file) {
    return file.expires_at && new Date(file.expires_at) < new Date();
}
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
    is_public    INTEGER DEFAULT 1,
    created_at   TEXT    DEFAULT (datetime('now'))
  );
  -- Migration: is_public für bestehende Datenbanken nachrüsten
  -- (ignoriert Fehler falls Spalte schon existiert)


  CREATE TABLE IF NOT EXISTS api_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    name         TEXT    NOT NULL,
    token_hash   TEXT    UNIQUE NOT NULL,
    prefix       TEXT    NOT NULL,
    last_used_at TEXT,
    created_at   TEXT    DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_files_user   ON files(user_id);
  CREATE INDEX IF NOT EXISTS idx_files_fileid ON files(file_id);
  CREATE INDEX IF NOT EXISTS idx_tokens_user  ON api_tokens(user_id);
  CREATE INDEX IF NOT EXISTS idx_tokens_hash  ON api_tokens(token_hash);
`);
try { db.exec(`ALTER TABLE files ADD COLUMN is_public INTEGER DEFAULT 1`); } catch { }
try { db.exec(`ALTER TABLE files ADD COLUMN expires_at TEXT`); } catch { }
try { db.exec(`ALTER TABLE files ADD COLUMN password_hash TEXT`); } catch { }

// Abgelaufene Dateien alle 10 Minuten löschen
function cleanupExpired() {
    const expired = db.prepare(`SELECT * FROM files WHERE expires_at IS NOT NULL AND expires_at < datetime('now')`).all();
    for (const f of expired) {
        try { fs.unlinkSync(path.join(UPLOAD_DIR, f.stored_name)); } catch { }
        db.prepare('DELETE FROM files WHERE id = ?').run(f.id);
    }
    if (expired.length) console.log(`[cleanup] ${expired.length} abgelaufene Datei(en) gelöscht`);
}
cleanupExpired();
setInterval(cleanupExpired, 10 * 60 * 1000);

// ── Redis-ready session store ─────────────────────────────────────────────────
// Optional env vars:
//   REDIS_URL=redis://127.0.0.1:6379  — enables Redis-backed sessions
//   REDIS_REQUIRED=true               — crash instead of falling back to memory
// Without REDIS_URL the default in-memory MemoryStore is used.
// MemoryStore is per-process and lost on restart — not safe for PM2 cluster mode.
let _sessionStoreType = 'memory';

function buildSessionStore() {
    const REDIS_URL = process.env.REDIS_URL;
    if (!REDIS_URL) {
        console.log('[session] No REDIS_URL — using in-memory MemoryStore (not cluster-safe)');
        return undefined; // express-session defaults to MemoryStore
    }
    let Redis, RedisStoreFactory;
    try {
        Redis = require('ioredis');
        RedisStoreFactory = require('connect-redis')(session);
    } catch {
        const warn = '[session] REDIS_URL set but ioredis/connect-redis not installed — run: npm install  Falling back to memory store.';
        console.warn(warn);
        if (process.env.REDIS_REQUIRED === 'true') throw new Error(warn);
        return undefined;
    }
    try {
        const client = new Redis(REDIS_URL, {
            lazyConnect: false,
            maxRetriesPerRequest: 3,
            connectTimeout: 5000,
            enableReadyCheck: true,
        });
        client.on('connect', () => {
            _sessionStoreType = 'redis';
            console.log('[session] Redis connected — sessions backed by Redis');
        });
        client.on('error', err => {
            _sessionStoreType = 'redis-degraded';
            console.warn('[session] Redis error:', err.message);
        });
        _sessionStoreType = 'redis-connecting';
        return new RedisStoreFactory({ client, prefix: 'sess:filehoster:', ttl: 7 * 24 * 60 * 60 });
    } catch (err) {
        const warn = `[session] Redis store init failed: ${err.message} — falling back to memory`;
        console.warn(warn);
        if (process.env.REDIS_REQUIRED === 'true') throw err;
        return undefined;
    }
}

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
    store: buildSessionStore(),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000,
    },
}));
app.use(express.static(path.join(__dirname, 'public')));

// ── Helpers ───────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    req.user = req.session.user;
    next();
}

// ── API tokens (EselShot desktop client) ──────────────────────────────────────
const TOKEN_PREFIX = 'esel_';
const MAX_TOKENS_PER_USER = 10;

function hashToken(raw) {
    return crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
}

function userFromToken(raw) {
    if (typeof raw !== 'string' || !raw.startsWith(TOKEN_PREFIX)) return null;
    const row = db.prepare(`
        SELECT t.id AS token_id, u.id, u.discord_id, u.username, u.avatar
        FROM api_tokens t JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = ?
    `).get(hashToken(raw));
    if (!row) return null;
    db.prepare("UPDATE api_tokens SET last_used_at = datetime('now') WHERE id = ?").run(row.token_id);
    return { id: row.id, discordId: row.discord_id, username: row.username, avatar: row.avatar };
}

// Accepts either the browser session cookie or `Authorization: Bearer esel_…`.
function requireUser(req, res, next) {
    if (req.session.user) { req.user = req.session.user; return next(); }
    const auth = req.headers.authorization || '';
    if (auth.startsWith('Bearer ')) {
        const user = userFromToken(auth.slice(7).trim());
        if (user) { req.user = user; return next(); }
    }
    res.status(401).json({ error: 'Unauthorized' });
}

// ── Rate limiting (in-memory, per-process) ────────────────────────────────────
// NOTE: Resets on restart and is not shared across PM2 cluster workers.
// TODO: Replace with rate-limiter-flexible + ioredis for cluster-safe limiting.
const _rlStore = new Map();
const _rlCleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of _rlStore) if (now > v.reset + 60_000) _rlStore.delete(k);
}, 5 * 60_000);
_rlCleanupInterval.unref();
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
app.get('/api/me', requireUser, (req, res) => {
    const { total_bytes } = db.prepare(
        'SELECT COALESCE(SUM(size), 0) AS total_bytes FROM files WHERE user_id = ?'
    ).get(req.user.id);
    res.json({ ...req.user, usedBytes: total_bytes, quotaBytes: MAX_TOTAL_BYTES_PER_USER });
});

app.get('/api/files', requireUser, (req, res) => {
    const files = db.prepare(
        `SELECT id, file_id, orig_name, mime_type, size, downloads, is_public, expires_at,
                password_hash IS NOT NULL AS has_password, created_at
         FROM files
         WHERE user_id = ?
           AND (expires_at IS NULL OR expires_at > datetime('now'))
         ORDER BY created_at DESC`
    ).all(req.user.id);
    res.json(files);
});

// Upload via busboy — streams directly to disk, no temp file in memory
app.post('/api/upload', uploadLimiter, requireUser, (req, res) => {
    const userId = req.user.id;

    const count = db.prepare('SELECT COUNT(*) as c FROM files WHERE user_id = ?').get(userId);
    if (count.c >= MAX_FILES_PER_USER) {
        return res.status(429).json({ error: `Datei-Limit erreicht (${MAX_FILES_PER_USER})` });
    }

    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    if (contentLength > MAX_FILE_SIZE + 1024) {
        return res.status(413).json({ error: 'Datei zu groß (max 500 MB)' });
    }

    // Check per-user storage quota (2 GB)
    const { total_bytes } = db.prepare(
        'SELECT COALESCE(SUM(size), 0) AS total_bytes FROM files WHERE user_id = ?'
    ).get(userId);
    if (total_bytes + contentLength > MAX_TOTAL_BYTES_PER_USER) {
        return res.status(413).json({ error: 'Speicherlimit erreicht (max. 2 GB pro Nutzer)' });
    }

    let bb;
    try {
        bb = busboy({ headers: req.headers, limits: { files: 1, fileSize: MAX_FILE_SIZE } });
    } catch {
        return res.status(400).json({ error: 'Ungültige Anfrage' });
    }

    let responded = false;
    let isPublic = 1;
    let expiresAtVal = null;
    let passwordHash = null;

    bb.on('field', (name, val) => {
        if (name === 'public') isPublic = val === '0' || val === 'false' ? 0 : 1;
        if (name === 'expires_in') expiresAtVal = expiresAt(val);
        if (name === 'password' && val) passwordHash = hashPassword(val);
    });

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
                    INSERT INTO files (file_id, orig_name, stored_name, mime_type, size, user_id, is_public, expires_at, password_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                `).run(fileId, safeName, storedName, String(mimeType || 'application/octet-stream'), bytesWritten, userId, isPublic, expiresAtVal, passwordHash);

                responded = true;
                res.json({
                    fileId,
                    url: `${PUBLIC_BASE_URL}/f/${fileId}/${encodeURIComponent(safeName)}`,
                    name: safeName,
                    is_public: isPublic,
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

app.delete('/api/files/:id', requireUser, (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id) || id < 1) return res.status(400).json({ error: 'Ungültige ID' });

    const file = db.prepare('SELECT * FROM files WHERE id = ? AND user_id = ?').get(id, req.user.id);
    if (!file) return res.status(404).json({ error: 'Datei nicht gefunden' });

    try { fs.unlinkSync(path.join(UPLOAD_DIR, file.stored_name)); } catch { }
    db.prepare('DELETE FROM files WHERE id = ?').run(id);
    res.json({ success: true });
});

app.patch('/api/files/:id/visibility', requireUser, (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id) || id < 1) return res.status(400).json({ error: 'Ungültige ID' });
    const file = db.prepare('SELECT * FROM files WHERE id = ? AND user_id = ?').get(id, req.user.id);
    if (!file) return res.status(404).json({ error: 'Datei nicht gefunden' });
    const isPublic = req.body?.public ? 1 : 0;
    db.prepare('UPDATE files SET is_public = ? WHERE id = ?').run(isPublic, id);
    res.json({ success: true, is_public: isPublic });
});

app.patch('/api/files/:id/expiry', requireUser, (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id) || id < 1) return res.status(400).json({ error: 'Ungültige ID' });
    const file = db.prepare('SELECT * FROM files WHERE id = ? AND user_id = ?').get(id, req.user.id);
    if (!file) return res.status(404).json({ error: 'Datei nicht gefunden' });
    const val = expiresAt(req.body?.expires_in);
    db.prepare('UPDATE files SET expires_at = ? WHERE id = ?').run(val, id);
    res.json({ success: true, expires_at: val });
});

app.patch('/api/files/:id/password', requireUser, (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id) || id < 1) return res.status(400).json({ error: 'Ungültige ID' });
    const file = db.prepare('SELECT * FROM files WHERE id = ? AND user_id = ?').get(id, req.user.id);
    if (!file) return res.status(404).json({ error: 'Datei nicht gefunden' });
    const pw = req.body?.password;
    const hash = pw ? hashPassword(pw) : null;
    db.prepare('UPDATE files SET password_hash = ? WHERE id = ?').run(hash, id);
    res.json({ success: true, password_set: !!hash });
});

// ── API token management (session-only: a token may not mint more tokens) ─────
app.get('/api/tokens', requireAuth, (req, res) => {
    const tokens = db.prepare(
        'SELECT id, name, prefix, last_used_at, created_at FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC'
    ).all(req.user.id);
    res.json(tokens);
});

app.post('/api/tokens', authLimiter, requireAuth, (req, res) => {
    const userId = req.user.id;
    const { c } = db.prepare('SELECT COUNT(*) AS c FROM api_tokens WHERE user_id = ?').get(userId);
    if (c >= MAX_TOKENS_PER_USER) {
        return res.status(429).json({ error: `Token-Limit erreicht (${MAX_TOKENS_PER_USER})` });
    }

    const name = String(req.body?.name || 'EselShot').replace(/[^\w .\-]/g, '').trim().slice(0, 40) || 'EselShot';
    const raw = TOKEN_PREFIX + crypto.randomBytes(24).toString('hex');

    db.prepare('INSERT INTO api_tokens (user_id, name, token_hash, prefix) VALUES (?, ?, ?, ?)')
        .run(userId, name, hashToken(raw), raw.slice(0, TOKEN_PREFIX.length + 6));

    // The plaintext token is returned exactly once — only its hash is stored.
    res.json({ token: raw, name });
});

app.delete('/api/tokens/:id', requireAuth, (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id) || id < 1) return res.status(400).json({ error: 'Ungültige ID' });
    const r = db.prepare('DELETE FROM api_tokens WHERE id = ? AND user_id = ?').run(id, req.user.id);
    if (r.changes === 0) return res.status(404).json({ error: 'Token nicht gefunden' });
    res.json({ success: true });
});

// ── Passwort-Eingabeseite ─────────────────────────────────────────────────────
function passwordPage(fileId, filename, wrong) {
    // Dateinamen stammen vom Nutzer - nie ungeprüft ins Markup.
    const safeName = String(filename).slice(0, 60).replace(/[&<>"']/g,
        c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    return `<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Passwort erforderlich – EselShot</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:#0d0d17;font-family:'Segoe UI',sans-serif;color:#e2e8f0}
.card{background:#12121c;border:1px solid #2b2b40;border-radius:16px;padding:36px 32px;
  width:100%;max-width:380px;text-align:center}
.lock{font-size:2.5rem;margin-bottom:12px}
h1{font-size:1.2rem;margin-bottom:6px}
.sub{color:#8b93a7;font-size:.85rem;margin-bottom:24px;word-break:break-all}
input{width:100%;padding:10px 14px;background:#1a1a2e;border:1px solid #2b2b40;border-radius:8px;
  color:#e2e8f0;font-size:1rem;outline:none;margin-bottom:12px}
input:focus{border-color:#818cf8}
.err{color:#ef4444;font-size:.85rem;margin-bottom:12px}
button{width:100%;padding:11px;background:#818cf8;border:none;border-radius:8px;
  color:#fff;font-size:1rem;font-weight:600;cursor:pointer}
button:hover{background:#6366f1}
</style></head><body>
<div class="card">
  <div class="lock">🔒</div>
  <h1>Passwort erforderlich</h1>
  <div class="sub">${safeName}</div>
  ${wrong ? '<div class="err">Falsches Passwort</div>' : ''}
  <form method="post" action="/f/${fileId}/unlock">
    <input type="password" name="pw" placeholder="Passwort eingeben" autofocus>
    <button type="submit">Entsperren</button>
  </form>
</div></body></html>`;
}

// Passwort prüfen: per POST, damit es nicht im Verlauf/Log der URL landet.
app.post('/f/:fileId/unlock', authLimiter, (req, res) => {
    const { fileId } = req.params;
    if (!/^[a-f0-9]{16}$/.test(fileId)) return res.status(404).send('Datei nicht gefunden');
    const file = db.prepare('SELECT * FROM files WHERE file_id = ?').get(fileId);
    if (!file || !file.password_hash) return res.status(404).send('Datei nicht gefunden');
    if (isExpired(file)) return res.status(410).send('Dieser Link ist abgelaufen');

    const submitted = String(req.body?.pw || '');
    const expected = Buffer.from(file.password_hash, 'utf8');
    const actual = Buffer.from(hashPassword(submitted), 'utf8');
    const ok = expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
    if (!ok) return res.status(401).send(passwordPage(fileId, file.orig_name, true));

    req.session[`pw_ok_${file.file_id}`] = true;
    res.redirect(`/f/${fileId}/${encodeURIComponent(file.orig_name)}`);
});

// ── File download/view ────────────────────────────────────────────────────────
app.get('/f/:fileId/:filename?', (req, res) => {
    const { fileId } = req.params;
    if (!/^[a-f0-9]{16}$/.test(fileId)) return res.status(404).send('Datei nicht gefunden');

    const file = db.prepare('SELECT * FROM files WHERE file_id = ?').get(fileId);
    if (!file) return res.status(404).send('Datei nicht gefunden');

    // Abgelaufen?
    if (isExpired(file)) return res.status(410).send('Dieser Link ist abgelaufen');

    // Privat: nur der Eigentümer darf zugreifen
    if (!file.is_public) {
        const user = req.session?.user || req.user;
        if (!user || user.id !== file.user_id) {
            return res.status(403).send('Diese Datei ist privat');
        }
    }

    // Passwortschutz - die Freigabe hängt an der Sitzung, nicht an der URL
    if (file.password_hash && !req.session[`pw_ok_${file.file_id}`]) {
        return res.status(401).send(passwordPage(fileId, file.orig_name, false));
    }

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

// Aktuelle EselShot-Version — bei jedem Build zusammen mit __version__ hochzählen
const ESELSHOT_VERSION = '1.3.0';

// ── EselShot-Download (öffentlich, keine Anmeldung) ──────────────────────────
// Die Datei wird beim Container-Build in /app/downloads mitgebacken. Byte-Range
// wird von express.static automatisch bedient, Cache lang, Dateien 500 MB max.
const ESELSHOT_DIR = path.join(__dirname, 'downloads');
const ESELSHOT_SETUP = path.join(ESELSHOT_DIR, 'EselShot-Setup.exe');

app.get('/eselshot', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'eselshot.html'));
});

app.get('/download/EselShot-Setup.exe', (req, res) => {
    if (!fs.existsSync(ESELSHOT_SETUP)) return res.status(404).send('EselShot-Setup.exe fehlt auf dem Server');
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="EselShot-Setup-${ESELSHOT_VERSION}.exe"`);
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.sendFile(ESELSHOT_SETUP);
});

app.get('/api/eselshot/version', (req, res) => {
    try {
        const st = fs.statSync(ESELSHOT_SETUP);
        res.json({ available: true, version: ESELSHOT_VERSION, size: st.size, mtime: st.mtime });
    } catch {
        res.json({ available: false });
    }
});

// ── Health ───────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', service: 'filehoster', uptime: process.uptime(), session_store: _sessionStoreType }));

// ── Start ─────────────────────────────────────────────────────────────────────
// ── 404 & Error handlers ─────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Nicht gefunden', path: req.path }));
app.use((err, req, res, next) => {
    console.error('[ERROR]', err.message);
    res.status(500).json({ error: 'Interner Serverfehler' });
});

const server = app.listen(PORT, () => console.log(`[files.eselbande.com] Running on port ${PORT}`));

function shutdown(signal) {
    console.log(`[SHUTDOWN] ${signal} received`);
    server.close(() => {
        try { db.close(); } catch (_) { }
        process.exit(0);
    });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
