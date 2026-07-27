# DOCKER001 — Container Running as Root

| Property     | Value    |
|--------------|----------|
| **ID**       | DOCKER001 |
| **Severity** | ⚠️ High |
| **Category** | Docker   |
| **Detector** | File     |

## Description

The Dockerfile does not specify a `USER` instruction, so the container process runs as root by default.

## Why It Matters

If an attacker gains remote code execution inside the container — through a dependency vulnerability, deserialization bug, or application flaw — they do so as root. Root inside a container can:

- Read and write any file in the container filesystem.
- Escalate to the host via kernel exploits or misconfigured volume mounts.
- Escape the container if the runtime is misconfigured (`--privileged`, writable `/proc`, etc.).

Running as a non-root user is a cheap, high-value hardening step.

## Vulnerable Example

```dockerfile
# ❌ No USER instruction — runs as root
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
CMD ["node", "dist/index.js"]
```

## Secure Example

```dockerfile
# ✅ Drop to the built-in 'node' user after setup
FROM node:20-alpine

WORKDIR /app

# Install deps as root (needed to write to /app)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy source
COPY --chown=node:node . .

# Switch to non-root before running the app
USER node

EXPOSE 3000
CMD ["node", "dist/index.js"]
```

The official `node` Docker images ship with a `node` user (UID 1000). Use `--chown=node:node` on `COPY` so the app files are owned by that user.

## Multi-stage build example

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
COPY --from=builder --chown=node:node /app/dist ./dist
COPY --from=builder --chown=node:node /app/package*.json ./
RUN npm ci --omit=dev
USER node
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

## Remediation

1. Add `USER node` after file setup and before `CMD`/`ENTRYPOINT`.
2. Use `COPY --chown=node:node` to set correct ownership.
3. If a custom user is needed: `RUN addgroup -S app && adduser -S app -G app` then `USER app`.
4. Avoid `USER root` anywhere after the initial setup phase.

## References

- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Snyk — 10 Docker Image Security Best Practices](https://snyk.io/blog/10-docker-image-security-best-practices/)
