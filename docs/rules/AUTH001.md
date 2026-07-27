# AUTH001 — Weak bcrypt Cost Factor

| Property   | Value            |
|------------|------------------|
| **ID**     | AUTH001          |
| **Severity** | ⚠️ High        |
| **Category** | Authentication |
| **Detector** | AST            |

## Description

bcrypt is invoked with a cost factor (salt rounds) lower than 12. A low cost factor makes brute-forcing hashed passwords significantly faster.

## Why It Matters

bcrypt is intentionally slow. The cost factor controls how many iterations the hashing algorithm runs. A cost of 10 runs ~1000 iterations; cost 12 runs ~4000. Each increment doubles the work. On modern hardware, cost 8 allows millions of guesses per second per GPU — fast enough to crack many real-world passwords from a leaked database in hours.

The OWASP Password Storage Cheat Sheet recommends a **minimum of 12**.

## Vulnerable Example

```typescript
// ❌ Cost factor 8 — too low for production
const hash = await bcrypt.hash(password, 8);

// ❌ bcrypt.hashSync with cost 4 — trivially brute-forceable
const hash = bcrypt.hashSync(password, 4);
```

## Secure Example

```typescript
// ✅ Cost factor 12 (good baseline for 2024)
const hash = await bcrypt.hash(password, 12);

// ✅ Read from config to allow future tuning without code changes
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS ?? '12', 10);
const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
```

## Calibrating the Cost Factor

Run this on your production hardware and choose the highest cost that completes in ≤ 300ms:

```typescript
import bcrypt from 'bcrypt';

for (let rounds = 10; rounds <= 15; rounds++) {
  const start = Date.now();
  await bcrypt.hash('test', rounds);
  console.log(`rounds=${rounds}: ${Date.now() - start}ms`);
}
```

## Remediation

1. Increase the cost factor to at least 12.
2. Re-hash passwords on next login using the higher cost (the old hash will still verify; replace on successful login).
3. Consider using **argon2** (winner of the Password Hashing Competition) as a modern alternative.

## References

- [OWASP — Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [bcrypt npm package](https://www.npmjs.com/package/bcrypt)
- [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
