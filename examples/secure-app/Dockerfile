# ✅ Secure Dockerfile following best practices
FROM node:20-alpine AS builder

WORKDIR /app

# Copy only dependency manifests first (layer cache)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy source with correct ownership
COPY --chown=node:node . .

# ────────────────────────────────────────────
FROM node:20-alpine AS runner

WORKDIR /app

# Copy from builder with correct ownership — never run as root
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/app.js ./

# Drop to non-root user — DOCKER001 ✅
USER node

EXPOSE 3000

# Health check — DOCKER003 ✅
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "app.js"]
