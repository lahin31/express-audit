# CASA001 — Refresh Token Stored Insecurely

| Property     | Value            |
|--------------|------------------|
| **ID**       | CASA001          |
| **Severity** | 🔴 Critical     |
| **Category** | CASA Readiness   |
| **Detector** | AST              |

> ⚠️ **Note:** CASA checks are Google CASA readiness indicators only. Passing these checks does not guarantee passing a full Google CASA assessment, which also covers organizational controls, infrastructure review, penetration testing, and operational practices.

## Description

An OAuth refresh token is stored without detectable encryption. Refresh tokens are long-lived credentials that grant ongoing access — they must be protected with the same rigour as passwords.

## Why It Matters

Google CASA (Cloud Application Security Assessment) and OWASP ASVS Level 2 require that long-lived tokens (refresh tokens) be stored encrypted at rest. If a database is breached, unencrypted refresh tokens give attackers permanent access to user accounts until each user actively revokes.

## Vulnerable Example

```typescript
// ❌ Refresh token stored as plain text
await db.query(
  'INSERT INTO sessions (user_id, refresh_token) VALUES (?, ?)',
  [userId, tokens.refresh_token],
);

// ❌ Plain assignment in model
user.refreshToken = oauthResponse.refresh_token;
await user.save();
```

## Secure Example

```typescript
import crypto from 'crypto';

const ENCRYPTION_KEY = Buffer.from(process.env.TOKEN_ENCRYPTION_KEY!, 'hex'); // 32 bytes
const IV_LENGTH = 16;

function encryptToken(plaintext: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function decryptToken(ciphertext: string): string {
  const data = Buffer.from(ciphertext, 'base64');
  const iv = data.subarray(0, IV_LENGTH);
  const tag = data.subarray(IV_LENGTH, IV_LENGTH + 16);
  const encrypted = data.subarray(IV_LENGTH + 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// ✅ Store encrypted
const encryptedToken = encryptToken(tokens.refresh_token);
await db.query(
  'INSERT INTO sessions (user_id, refresh_token_enc) VALUES (?, ?)',
  [userId, encryptedToken],
);
```

Or delegate to a managed KMS:

```typescript
import { KMSClient, EncryptCommand } from '@aws-sdk/client-kms';

const kms = new KMSClient({ region: 'us-east-1' });
const { CiphertextBlob } = await kms.send(
  new EncryptCommand({
    KeyId: process.env.KMS_KEY_ID,
    Plaintext: Buffer.from(tokens.refresh_token),
  }),
);
await storeToken(userId, Buffer.from(CiphertextBlob!).toString('base64'));
```

## Remediation

1. Encrypt refresh tokens with AES-256-GCM before writing to any storage.
2. Store the encryption key in a KMS (AWS KMS, GCP Cloud KMS, HashiCorp Vault).
3. Never log, cache in memory dumps, or include in error reports.
4. Implement token rotation — issue a new refresh token on every use.
5. Store only a hash of single-use tokens for revocation lookup.

## References

- [Google CASA Requirements](https://appdefensealliance.dev/casa)
- [OWASP ASVS v4 — V3.5 Token-based Sessions](https://owasp.org/www-project-application-security-verification-standard/)
- [RFC 6749 — OAuth 2.0 Refresh Tokens](https://tools.ietf.org/html/rfc6749#section-6)
- [NIST SP 800-57 — Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
