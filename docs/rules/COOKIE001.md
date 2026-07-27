# COOKIE001 — Insecure Cookie Configuration

| Property   | Value      |
|------------|------------|
| **ID**     | COOKIE001  |
| **Severity** | ⚠️ High  |
| **Category** | Cookies  |
| **Detector** | AST      |

## Description

A cookie is set without one or more of the recommended security attributes: `httpOnly`, `secure`, or `sameSite`.

## Why It Matters

| Missing flag | Attack enabled |
|---|---|
| `httpOnly: false` | JavaScript can read the cookie — XSS becomes session theft |
| `secure: false` | Cookie sent over plain HTTP — network sniffing intercepts it |
| `sameSite` absent | Cross-site request forgery (CSRF) is much easier to exploit |

## Vulnerable Examples

```typescript
// ❌ No options at all
res.cookie('session_id', token);

// ❌ Missing httpOnly — JavaScript-accessible
res.cookie('auth', token, { secure: true, sameSite: 'strict' });

// ❌ Explicitly disabled httpOnly
res.cookie('auth', token, { httpOnly: false, secure: true });
```

## Secure Example

```typescript
// ✅ All three security attributes set
res.cookie('auth', token, {
  httpOnly: true,                                // Not accessible via document.cookie
  secure: process.env.NODE_ENV === 'production', // HTTPS-only in production
  sameSite: 'strict',                            // No cross-site sending
  maxAge: 15 * 60 * 1000,                        // 15 minutes
  path: '/',
});
```

Use `'lax'` instead of `'strict'` for `sameSite` if your app needs to work with top-level navigations from external links (e.g. OAuth redirects).

## Remediation

1. Add `httpOnly: true` to every cookie that does not need to be accessed by JavaScript (virtually all auth cookies).
2. Add `secure: true` (or `secure: process.env.NODE_ENV === 'production'`).
3. Add `sameSite: 'strict'` or `sameSite: 'lax'`.
4. Set `maxAge` or `expires` to limit cookie lifetime.
5. Scope cookies with `path` and `domain` appropriately.

## References

- [MDN — Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
- [OWASP — Secure Cookie Attribute](https://owasp.org/www-community/controls/SecureCookieAttribute)
- [OWASP — HttpOnly Cookie Attribute](https://owasp.org/www-community/HttpOnly)
- [Express res.cookie() API](https://expressjs.com/en/api.html#res.cookie)
