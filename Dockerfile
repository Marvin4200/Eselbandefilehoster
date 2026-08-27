FROM node:20-bookworm-slim

WORKDIR /app
ENV NODE_ENV=production

COPY --chown=node:node package*.json ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

COPY --chown=node:node . .

EXPOSE 3011
USER node
CMD ["npm", "start"]
