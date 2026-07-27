# OAUTH001 — Missing PKCE in OAuth Flow

| Property     | Value      |
|--------------|------------|
| **ID**       | OAUTH001   |
| **Severity** | ⚠️ High   |
| **Category** | OAuth      |
| **Detector** | AST        |

## Description

An OAuth 2.0 Authorization Code flow is configured without PKCE (Proof Key for Code Exchange, RFC 7636). PKCE prevents authorization code interception attacks.

## Why It Matters

Without PKCE, if an attacker intercepts the authorization code (via a malicious redirect, open redirect, or referrer leakage), they can exchange it for tokens without knowing the original code verifier. PKCE is now **required** for all public clients and **strongly recommended** for confidential clients by the OAuth 2.0 Security Best Current Practice (RFC 9700).

Google CASA and most modern OAuth servers require PKCE.

## How PKCE Works

1. **Client generates** a random `code_verifier` (43–128 chars, URL-safe).
2. **Client hashes it** with SHA-256 → `code_challenge = BASE64URL(SHA256(code_verifier))`.
3. `code_challenge` is sent with the authorization request.
4. `code_verifier` is sent with the token request.
5. The server verifies the hash — proves the token requester initiated the auth flow.

## Vulnerable Example

```typescript
// ❌ No PKCE — authorization code can be stolen and exchanged
const strategy = new OAuth2Strategy(
  {
    authorizationURL: 'https://accounts.google.com/o/oauth2/auth',
    tokenURL: 'https://oauth2.googleapis.com/token',
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
  },
  verifyCallback,
);
```

## Secure Example (openid-client)

```typescript
import { Issuer, generators } from 'openid-client';

const google = await Issuer.discover('https://accounts.google.com');
const client = new google.Client({
  client_id: process.env.GOOGLE_CLIENT_ID!,
  client_secret: process.env.GOOGLE_CLIENT_SECRET!,
  redirect_uris: ['https://yourapp.com/auth/callback'],
  response_types: ['code'],
});

// ✅ PKCE with S256
app.get('/auth/login', (req, res) => {
  const codeVerifier = generators.codeVerifier();
  const codeChallenge = generators.codeChallenge(codeVerifier);
  const state = generators.state();

  req.session.codeVerifier = codeVerifier;
  req.session.state = state;

  const url = client.authorizationUrl({
    scope: 'openid email profile',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state,
  });
  res.redirect(url);
});

app.get('/auth/callback', async (req, res) => {
  const params = client.callbackParams(req);
  const tokens = await client.callback(
    'https://yourapp.com/auth/callback',
    params,
    {
      code_verifier: req.session.codeVerifier,
      state: req.session.state,
    },
  );
  // ...
});
```

## Remediation

1. Use `openid-client` or a library with built-in PKCE support.
2. Always use `code_challenge_method: 'S256'` (plain is not secure).
3. Generate a fresh `code_verifier` per authorization request.
4. Store `code_verifier` in the server-side session (never in a cookie or URL).

## References

- [RFC 7636 — PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/rfc9700)
- [Google Identity — OAuth 2.0 for Web Server Applications](https://developers.google.com/identity/protocols/oauth2/web-server)
- [openid-client documentation](https://github.com/panva/node-openid-client)
