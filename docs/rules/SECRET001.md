# SECRET001–010 — Hardcoded Secrets

| Property     | Value        |
|--------------|--------------|
| **ID**       | SECRET001–010 |
| **Severity** | 🔴 Critical / ⚠️ High |
| **Category** | Secrets      |
| **Detector** | Regex        |

## Description

A secret credential — API key, private key, database password, or service token — is found hardcoded in source code as a string literal.

## Why It Matters

Hardcoded secrets are one of the most common and highest-impact security mistakes. They are trivially discoverable:

- **Git history** — The secret persists in commit history even after removal.
- **npm publish** — Source maps and bundled code may be published to the registry.
- **Compiled artefacts** — Docker layers, minified bundles, and APKs can be extracted.
- **Contractor/contributor access** — Anyone with read access to the repo has the secret.

## Covered Secret Types

| Rule ID    | Type                       | Severity |
|------------|----------------------------|----------|
| SECRET001  | AWS Access Key ID          | Critical |
| SECRET002  | AWS Secret Access Key      | Critical |
| SECRET003  | Google API Key             | Critical |
| SECRET004  | Stripe Secret Key          | Critical |
| SECRET005  | Stripe Publishable Key     | High     |
| SECRET006  | GitHub Personal Access Token | Critical |
| SECRET007  | PEM Private Key            | Critical |
| SECRET008  | Hardcoded password variable | High    |
| SECRET009  | Database connection string with credentials | Critical |
| SECRET010  | SendGrid API Key           | Critical |

## Vulnerable Examples

```typescript
// ❌ AWS key
const s3 = new S3({ accessKeyId: 'AKIAIOSFODNN7EXAMPLE' });

// ❌ Stripe
const stripe = Stripe('sk_live_4eC39HqLyjWDarjtT1zdp7dc');

// ❌ Database URL with credentials
const db = new Pool({ connectionString: 'postgresql://admin:p4ssw0rd@prod-db:5432/myapp' });

// ❌ Password variable
const adminPassword = 'SuperSecret123!';
```

## Secure Example

```typescript
// ✅ All secrets from environment
import { S3 } from '@aws-sdk/client-s3';
import Stripe from 'stripe';
import { Pool } from 'pg';

const s3 = new S3({
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
  },
});

const stripe = Stripe(process.env.STRIPE_SECRET_KEY!);

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
```

## Remediation

1. **Rotate immediately** — Any secret found in source or history is compromised. Revoke and reissue it now.
2. Remove the hardcoded value and replace with `process.env.SECRET_NAME`.
3. Add the secret to your secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler, 1Password Secrets Automation).
4. Add `.env` to `.gitignore` and never commit it.
5. Install a pre-commit hook to prevent future leaks:

```bash
npx husky add .husky/pre-commit "npx express-audit . --fail-on critical"
```

6. Scan git history for already-committed secrets:

```bash
npx trufflehog git file://. --since-commit HEAD~50
```

## References

- [OWASP — Use of Hard-coded Credentials (CWE-798)](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)
- [GitHub — Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [Google Cloud — Secret Manager](https://cloud.google.com/secret-manager)
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
