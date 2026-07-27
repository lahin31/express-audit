# express-audit

> Static security analysis for Express.js applications. Detect authentication, authorization, cookie, OAuth, and configuration mistakes before they reach production.

[![npm version](https://badge.fury.io/js/express-audit.svg)](https://www.npmjs.com/package/express-audit)
[![CI](https://github.com/yourusername/express-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/express-audit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Run it in any Express.js project:

```bash
npx express-audit
```

No configuration required.

---

## Why express-audit?

Dependency scanners tell you about CVEs in packages you installed. express-audit tells you about security mistakes in code you wrote.

Those are different problems. A dependency scanner won't tell you that your `jwt.sign()` call has no expiry, that your session secret is hardcoded, or that `cors()` is called without an origin allowlist. Those are application-level misconfigurations — and they're the ones that show up in bug bounty reports and breach postmortems.

---

## How it works

express-audit parses your source files into an Abstract Syntax Tree (AST) using Babel, then runs each rule as a structured visitor over that tree. Rules don't search for strings — they inspect typed AST nodes, so `jwt.sign(payload, "secret")` is identified as a call expression with a string literal in the secret argument position, not a pattern match against the characters `jwt.sign`.

```
Your Express Project
        │
        ▼
┌───────────────────┐
│   Babel Parser    │  Parses JS/TS into a typed AST.
│                   │  Handles ESM, CJS, JSX, decorators.
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│       AST         │  Nodes represent real code constructs:
│                   │  CallExpression, ObjectExpression,
│                   │  MemberExpression, ImportDeclaration…
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Route & Config    │  Rules identify Express-specific patterns:
│  Discovery        │  router.delete(), res.cookie(), cors(),
│                   │  session(), jwt.sign(), app.use()…
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│   Rule Engine     │  Each rule runs independently.
│                   │  Returns findings with file, line,
│                   │  severity, impact, and fix.
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│     Report        │  CLI · JSON · HTML · SARIF
└───────────────────┘
```

This is why a finding like `COOKIE001` is not "the word `httpOnly` is absent from the file" — it's "a `CallExpression` matching `res.cookie()` has an `ObjectExpression` argument where the `httpOnly` property is either missing or set to `false`." The distinction matters for accuracy and for keeping false positives low.

---

## How it's different

**It knows what Express APIs mean.** Rules understand what `res.cookie()`, `jwt.sign()`, `session()`, and `cors()` do. A generic linter sees function calls. express-audit sees a cookie being set without `httpOnly`, a JWT being signed without `expiresIn`, or a session being configured with a hardcoded secret — and flags the specific option that's missing or wrong.

**It analyzes supported Express routing and middleware patterns.** For common patterns — `router.delete('/users/:id', handler)` with no middleware argument, or `app.use(cors())` with no options — it can identify what's absent. It works at the AST level on what is written in a single file. It does not perform cross-file data flow analysis, cannot follow middleware registered through factories or dependency injection, and will miss patterns it wasn't written to recognise. False negatives are possible; the tool is conservative to keep false positives low.

**Every finding is actionable.** File path, line number, security impact, and a concrete fix — in every report.

---

## Why AI isn't enough

A good LLM can review a file, spot a missing `httpOnly` flag, and suggest a fix in seconds. So why run a separate tool?

**AI is reactive. express-audit runs automatically.**
You have to remember to ask an AI to review your code. express-audit runs on every push, on every PR, without anyone remembering to prompt it. The finding that gets caught is the one that happens at 2am on a Friday when no one is asking for a review.

**AI results vary. express-audit results don't.**
The same code run through express-audit today and in six months produces the same findings. An LLM might catch the same issue, miss it, phrase it differently, or confidently suggest a fix that introduces a different vulnerability. For a security gate in CI, non-determinism is a problem.

**Project-wide analysis, not file-by-file review.**
AI typically reviews the code you provide. express-audit analyzes the project as a whole and produces a consistent report suitable for CI.

**AI output is not auditable.**
When a finding appears in a SARIF report uploaded to GitHub Code Scanning, there's a traceable rule ID, a line number, a severity, and a reference. That's something you can attach to a ticket, close in a PR, and demonstrate to a security team. "I asked GPT and it said it looked fine" is not.

**They work well together.**
express-audit tells you *what* is wrong and *where*. An LLM is useful for explaining *why* it matters in your specific codebase, drafting a fix, or reviewing a proposed remediation. Use express-audit to find issues systematically, and AI to help resolve them.

---

## Quick Start

```bash
# Audit the current directory
npx express-audit

# Output JSON (useful for CI pipelines or custom tooling)
npx express-audit --json > report.json

# Generate a self-contained HTML report
npx express-audit --html > report.html

# SARIF format for GitHub Code Scanning
npx express-audit --sarif > results.sarif

# Fail CI on any critical or high finding
npx express-audit --fail-on high
```

---

## Example Output

```
Express Audit v1.0.0

📊 Security Score: 78/100

🔴 Critical (3)
────────────────────────────────────────────────────────────
JWT001 | Hardcoded JWT Secret
Location: src/auth/jwt.ts:18
Impact: Allows an attacker to forge valid tokens and impersonate any user.
Fix: Use environment variables: jwt.sign(payload, process.env.JWT_SECRET)

SESSION001 | Hardcoded Session Secret
Location: src/app.ts:21
Impact: Session cookies can be forged, bypassing authentication entirely.
Fix: Use: secret: process.env.SESSION_SECRET

AUTHZ002 | Admin Route Unprotected
Location: src/routes/admin.ts:54
Impact: Any user can access admin functionality.
Fix: Add auth + RBAC: router.get("/admin", authenticate, requireRole("admin"), handler)

⚠️  High (4)
────────────────────────────────────────────────────────────
AUTH001 | Weak bcrypt Cost Factor
CORS001 | CORS Allows All Origins
COOKIE001 | Cookie Missing Security Options
HTTP001 | Helmet Middleware Missing

📋 Medium (3)
────────────────────────────────────────────────────────────
CSP001 | Missing Content Security Policy
RATE001 | No Rate Limiting Detected
PROD003 | Missing Trust Proxy Configuration

ℹ️  Low (3)
────────────────────────────────────────────────────────────
HEADER001 | X-Powered-By Header Enabled
PROD001 | Missing Health Check Endpoint
PROD002 | Missing Graceful Shutdown

📈 Category Scores
────────────────────────────────────────────────────────────
Authentication             30%  ██████░░░░░░░░░░░░░░
Authorization              65%  █████████████░░░░░░░
HTTP Security              83%  ████████████████░░░░
Cookies                    90%  ██████████████████░░
Production Readiness       96%  ███████████████████░
```

> **About the Security Score**
>
> The score is a weighted heuristic based on finding severity across rule categories. A score of 100 means no findings were detected — it does not mean the application is secure. Use it to track improvement over time and to prioritise which findings to address first. Do not present it as a security certification.

---

## What It Checks

### Authentication
Hardcoded JWT secrets, missing token expiration, weak bcrypt cost factors, plaintext password comparisons.

### Authorization
Sensitive routes (`DELETE`, `PATCH`, `PUT`) without authentication middleware, admin endpoints without role checks.

### Input Validation
Direct use of `req.body` and `req.query` without a validation library (Zod, Joi, express-validator).

### SQL Security
Raw query string concatenation with user input, unsafe Prisma `$queryRawUnsafe` / `$executeRawUnsafe` calls.

### HTTP Security
Missing Helmet middleware, Content Security Policy, and `X-Powered-By` header exposure.

### Cookies & Sessions
Missing `httpOnly`, `secure`, and `sameSite` flags; hardcoded session secrets; insecure `express-session` configuration.

### CORS
Wildcard origin (`*`), missing origin restriction, `credentials: true` combined with wildcard origins.

### Rate Limiting
No rate limiting middleware detected on any endpoint, including authentication routes.

### Secrets
Hardcoded AWS keys, Google API keys, Stripe keys, GitHub tokens, PEM private keys, database connection strings, and SMTP credentials.

### Logging
Passwords, tokens, and API keys written to log output; full request body logging; stack traces returned to clients.

### Error Handling
Raw error objects returned in HTTP responses, missing global error-handler middleware.

### OAuth Security & Google CASA Readiness
Missing PKCE, state parameter validation, and nonce validation; overly broad OAuth scopes; unencrypted refresh token storage; missing token revocation.

> express-audit includes Google CASA readiness checks that can be verified through static analysis. It is **not** a replacement for a full Google CASA assessment. A complete assessment also covers organizational controls, infrastructure review, penetration testing, and operational practices that cannot be evaluated statically.

### Production Readiness
Missing health check endpoints, graceful shutdown handlers, trust proxy configuration, and compression middleware.

### Docker
Container running as root, `:latest` image tags, missing `HEALTHCHECK`, secrets baked into the image, and `COPY . .` without a `.dockerignore`.

---

## Rule Reference

Dozens of built-in rules across 15 categories. Full documentation for each rule — including vulnerable examples, secure examples, and remediation steps — is in [`docs/rules/`](./docs/rules/).

| Prefix | Category | Rules |
|---|---|---|
| `JWT`, `AUTH` | Authentication | JWT001, JWT002, AUTH001, AUTH002 |
| `AUTHZ` | Authorization | AUTHZ001, AUTHZ002 |
| `VAL` | Input Validation | VAL001, VAL002 |
| `SQL` | SQL Security | SQL001, SQL002 |
| `HTTP`, `HEADER`, `CSP` | HTTP Security | HTTP001, CSP001, HEADER001 |
| `COOKIE`, `SESSION` | Cookies & Sessions | COOKIE001, SESSION001 |
| `CORS` | CORS | CORS001 |
| `RATE` | Rate Limiting | RATE001 |
| `SECRET` | Secrets | SECRET001–010 |
| `LOG` | Logging | LOG001, LOG002, LOG003 |
| `ERR` | Error Handling | ERR001, ERR002 |
| `OAUTH` | OAuth Security | OAUTH001, OAUTH002, OAUTH003 |
| `CASA` | Google CASA Readiness | CASA001–CASA005 |
| `PROD` | Production Readiness | PROD001–PROD004 |
| `DOCKER` | Docker | DOCKER001–DOCKER005 |

---

## Configuration

Create an `express-audit.config.js` file in your project root to customise behaviour:

```js
// express-audit.config.js
export default {
  rules: {
    // Disable rules that don't apply to your project
    disabled: ['PROD004'],

    // Override severity for specific rules
    overrides: {
      'RATE001': { severity: 'high' },
    },
  },

  ignore: {
    // Skip generated or third-party files
    paths: ['src/generated/**', '**/*.test.ts'],
  },
};
```

Supported config file names: `express-audit.config.js`, `express-audit.config.mjs`, `.express-audit.json`, `.express-auditrc`.

---

## CI Integration

### Fail on high-severity findings

```yaml
# .github/workflows/security.yml
- name: Run express-audit
  run: npx express-audit --fail-on high
```

### Upload SARIF to GitHub Code Scanning

```yaml
- name: Run express-audit
  run: npx express-audit --sarif > results.sarif

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Programmatic API

```typescript
import { audit } from 'express-audit';

const result = await audit('./my-express-app');

console.log(`Score: ${result.score}/100`);
console.log(`Findings: ${result.findings.length}`);

for (const finding of result.findings) {
  console.log(`[${finding.severity.toUpperCase()}] ${finding.ruleId}: ${finding.title}`);
  if (finding.filePath) console.log(`  at ${finding.filePath}:${finding.line ?? ''}`);
}
```

You can also register only the rules you need:

```typescript
import { AuditEngine, authenticationRules, sqlRules } from 'express-audit';

const engine = new AuditEngine({ rules: { disabled: ['JWT002'] } });
engine.registerRules([...authenticationRules, ...sqlRules]);

const result = await engine.audit('./my-project');
```

---

## Architecture

```
src/
  cli.ts              — CLI entry point
  index.ts            — Programmatic API
  core/
    engine.ts         — Rule runner and scoring
    ast-helpers.ts    — Shared Babel AST utilities
    config-loader.ts  — Config file discovery
  parser/             — Babel parser wrapper
  reporters/          — CLI, JSON, HTML, SARIF formatters
  rules/              — growing rule library across 15 categories

tests/                — unit and integration tests
docs/rules/           — Per-rule documentation
examples/             — Vulnerable and secure Express apps
```

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to write a rule, what tests are required, and the PR process.

---

## Roadmap

- [ ] NestJS, Fastify, Hono, and Koa support via framework adapters
- [ ] VS Code extension
- [ ] Custom rule SDK with a plugin entry point
- [ ] Baseline files — suppress known findings, surface only new ones
- [ ] GitLab CI template

---

## License

MIT © 2024
