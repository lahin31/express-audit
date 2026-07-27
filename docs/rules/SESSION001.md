# SESSION001 — Insecure Session Configuration

| Property     | Value                                          |
|--------------|------------------------------------------------|
| **ID**       | SESSION001                                     |
| **Severity** | Critical / High / Medium (depends on sub-rule) |
| **Category** | Sessions                                       |
| **Detector** | AST                                            |

## Description

`express-session` is configured with one or more insecure settings: a hardcoded secret, `saveUninitialized: true`, `resave: true`, or insecure cookie flags.

## Why It Matters

Sessions are the backbone of stateful authentication. Misconfiguring them creates a chain of vulnerabilities:

| Misconfiguration | Risk |
|---|---|
| Hardcoded secret | Anyone with source access can forge session cookies |
| `saveUninitialized: true` | Enables session fixation; creates storage bloat |
| `resave: true` | Race conditions, unnecessary writes |
| Cookie missing `httpOnly` | XSS steals session token |
| Cookie missing `secure` | Session token sent over HTTP |

## Vulnerable Example

```typescript
// ❌ Every option is wrong
app.use(session({
  secret: 'keyboard-cat',          // Hardcoded
  saveUninitialized: true,         // Session fixation risk
  resave: true,                    // Unnecessary writes
  cookie: {
    httpOnly: false,               // XSS-accessible
    secure: false,                 // Sent over HTTP
  },
}));
```

## Secure Example

```typescript
import session from 'express-session';
import RedisStore from 'connect-redis';
import { redis } from './redis.js';

app.use(
  session({
    secret: process.env.SESSION_SECRET!,   // From environment
    saveUninitialized: false,               // Only save when something stored
    resave: false,                          // Don't save if unmodified
    rolling: true,                          // Reset expiry on activity
    store: new RedisStore({ client: redis }),
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 30 * 60 * 1000,              // 30-minute idle timeout
    },
  }),
);
```

## Remediation

1. Move `secret` to `process.env.SESSION_SECRET` — generate with `crypto.randomBytes(64).toString('hex')`.
2. Set `saveUninitialized: false` and `resave: false`.
3. Use a persistent store (Redis, Postgres) — the default MemoryStore leaks memory and doesn't survive restarts.
4. Set `cookie: { httpOnly: true, secure: true, sameSite: 'strict' }`.
5. Set `maxAge` to limit idle session lifetime.

## References

- [express-session documentation](https://www.npmjs.com/package/express-session)
- [OWASP — Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
