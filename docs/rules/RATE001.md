# RATE001 — No Rate Limiting Detected

| Property     | Value           |
|--------------|-----------------|
| **ID**       | RATE001         |
| **Severity** | 📋 Medium      |
| **Category** | Rate Limiting   |
| **Detector** | AST             |

## Description

No rate-limiting middleware is detected in the application entry file. Without rate limiting, all endpoints — including authentication — are open to brute-force and denial-of-service attacks.

## Why It Matters

OWASP API Security Top 10 2023 lists **Unrestricted Resource Consumption (API4)** as a top threat. Specific risks without rate limiting:

- **Brute-force attacks** — Attackers can try millions of password/token combinations.
- **Credential stuffing** — Automated login attempts with leaked credential lists.
- **Denial of service** — Flood requests exhaust CPU, memory, or database connections.
- **Account enumeration** — Observe response-time differences at scale to discover valid usernames.

## Vulnerable Example

```typescript
// ❌ No rate limiting — login can be hammered indefinitely
app.post('/login', async (req, res) => {
  const user = await db.findUser(req.body.email);
  const ok = await bcrypt.compare(req.body.password, user.hash);
  res.json({ ok });
});
```

## Secure Example

```typescript
import rateLimit from 'express-rate-limit';

// ✅ Global rate limit
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,    // Return RateLimit-* headers
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});
app.use(globalLimiter);

// ✅ Stricter limit on auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true, // Only count failed attempts
});

app.post('/login',   authLimiter, loginHandler);
app.post('/register', authLimiter, registerHandler);
app.post('/password-reset', authLimiter, passwordResetHandler);
```

## Remediation

```bash
npm install express-rate-limit
```

1. Apply a global limiter to all routes.
2. Apply a strict limiter (max 5–10 per 15 min) to authentication and password-reset endpoints.
3. For distributed deployments, use a shared store like Redis:

```bash
npm install rate-limit-redis
```

```typescript
import { RedisStore } from 'rate-limit-redis';
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  store: new RedisStore({ sendCommand: (...args) => redis.sendCommand(args) }),
});
```

## References

- [express-rate-limit documentation](https://www.npmjs.com/package/express-rate-limit)
- [OWASP API Security — Unrestricted Resource Consumption](https://owasp.org/www-project-api-security/)
- [OWASP — Blocking Brute Force Attacks](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
