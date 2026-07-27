# ❌ This is an INTENTIONALLY INSECURE Dockerfile for testing express-audit
# DO NOT USE IN PRODUCTION

FROM node:latest

WORKDIR /app

COPY . .

ENV DB_PASSWORD=supersecret123
ENV API_KEY=sk_live_abcdef123456

RUN npm install

# Running as root — DOCKER001
# Using :latest tag — DOCKER002
# No HEALTHCHECK — DOCKER003
# Secrets in ENV — DOCKER004
# COPY . . — DOCKER005

EXPOSE 3000

CMD ["node", "app.js"]
