# HTTP001 — Helmet Middleware Missing

| Property     | Value         |
|--------------|---------------|
| **ID**       | HTTP001       |
| **Severity** | ⚠️ High      |
| **Category** | HTTP Security |
| **Detector** | AST           |

## Description

The `helmet` middleware is not present in the application entry file. Without it, Express sets no security-related HTTP headers, leaving the application exposed to a range of common web attacks.

## Why It Matters

Helmet sets **11 security headers** by default, each mitigating a specific class of attack:

| Header | Mitigates |
|---|---|
| `Content-Security-Policy` | XSS, data injection |
| `X-Content-Type-Options: nosniff` | MIME-type sniffing |
| `X-Frame-Options: SAMEORIGIN` | Clickjacking |
| `Strict-Transport-Security` | Protocol downgrade, MITM |
| `X-DNS-Prefetch-Control` | Information leakage |
| `Referrer-Policy` | Referrer leakage |
| `Permissions-Policy` | Feature abuse |
| `Cross-Origin-Opener-Policy` | Spectre-style attacks |
| `Cross-Origin-Resource-Policy` | Cross-origin data reads |
| `X-Permitted-Cross-Domain-Policies` | Adobe Flash/PDF attacks |
| Remove `X-Powered-By` | Technology fingerprinting |

## Vulnerable Example

```typescript
// ❌ No helmet — Express sets almost no security headers
const express = require('express');
const app = express();

app.get('/', (req, res) => res.send('Hello'));
app.listen(3000);
```

## Secure Example

```typescript
import express from 'express';
import helmet from 'helmet';

const app = express();

// ✅ Enables all defaults
app.use(helmet());

// ✅ With custom CSP (recommended for production)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'https://cdn.yourdomain.com'],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
  }),
);
```

## Remediation

```bash
npm install helmet
```

Add `app.use(helmet())` **before** any route definitions.

## References

- [Helmet.js documentation](https://helmetjs.github.io/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
