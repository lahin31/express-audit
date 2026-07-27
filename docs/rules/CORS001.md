# CORS001 — CORS Wildcard Origin

| Property   | Value     |
|------------|-----------|
| **ID**     | CORS001   |
| **Severity** | ⚠️ High |
| **Category** | CORS     |
| **Detector** | AST     |

## Description

The CORS middleware is configured to allow all origins (`*`), or is called without any options, which defaults to allowing all origins.

## Why It Matters

When `Access-Control-Allow-Origin: *` is returned, any website can make cross-origin requests to your API. Combined with cookies or other credentials, this can enable cross-site request forgery and data theft. Browsers do reject `origin: "*"` combined with `credentials: true`, but the misconfigured intent still indicates broken security thinking and will cause confusing runtime errors.

## Vulnerable Examples

```typescript
// ❌ No options — allows all origins by default
app.use(cors());

// ❌ Explicit wildcard
app.use(cors({ origin: '*' }));

// ❌ Wildcard + credentials (browser will reject, but intent is wrong)
app.use(cors({ origin: '*', credentials: true }));
```

## Secure Example

```typescript
// ✅ Explicit allowlist
const allowedOrigins = [
  'https://app.yourdomain.com',
  'https://admin.yourdomain.com',
];

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }),
);

// ✅ Dynamic origin with strict validation
app.use(
  cors({
    origin(requestOrigin, callback) {
      if (!requestOrigin || allowedOrigins.includes(requestOrigin)) {
        callback(null, true);
      } else {
        callback(new Error(`CORS: origin ${requestOrigin} not allowed`));
      }
    },
    credentials: true,
  }),
);
```

## Remediation

1. Replace `cors()` / `cors({ origin: '*' })` with an explicit allowlist.
2. Set `credentials: true` only when cookies or auth headers are needed.
3. Restrict `methods` and `allowedHeaders` to only what your API uses.
4. In development, add `localhost` origins conditionally based on `NODE_ENV`.

## References

- [MDN — Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [OWASP — CORS Origin Header Scrutiny](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)
- [express/cors documentation](https://expressjs.com/en/resources/middleware/cors.html)
- [W3C CORS Specification](https://www.w3.org/TR/cors/)
