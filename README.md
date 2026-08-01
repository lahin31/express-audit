# express-audit

> Static security analysis for Express.js applications. Detect authentication, authorization, cookie, OAuth, configuration, and performance issues before they reach production.

[![npm version](https://img.shields.io/npm/v/express-audit.svg?style=flat-square&color=cb3837&logo=npm)](https://www.npmjs.com/package/express-audit)
[![npm downloads](https://img.shields.io/npm/dm/express-audit?style=flat-square&color=cb3837)](https://www.npmjs.com/package/express-audit)
[![CI](https://github.com/JSExplore/express-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/JSExplore/express-audit/actions/workflows/ci.yml)
[![Security Audit](https://github.com/JSExplore/express-audit/actions/workflows/security-audit.yml/badge.svg)](https://github.com/JSExplore/express-audit/actions/workflows/security-audit.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square&logo=node.js)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/built%20with-TypeScript-3178c6?style=flat-square&logo=typescript)](https://www.typescriptlang.org)

Run it in any Express.js project:

```bash
npx express-audit
```

No configuration required.

## Trust & Security

express-audit is designed to be deterministic, transparent, and privacy-friendly.

**Static analysis only.** The tool reads your source files and produces a report. It never executes application code, spawns a server, or runs test suites.

**No network requests.** Analysis runs entirely offline. No data is sent anywhere during or after a scan.

**No telemetry or usage tracking.** express-audit collects nothing. There are no analytics, no crash reporters, and no phone-home mechanisms of any kind.

**`.env` files are never read.** Files matching `.env`, `.env.*`, or `*.env` are excluded from the file discovery step before any rule runs. A secret in `.env.production` will never appear in a finding or a report.

**Open source and fully auditable.** Every rule, every scoring algorithm, and every byte of the analysis engine is in this repository. You can read exactly what runs against your code before you run it.

**Every rule maps to a published standard.** All findings reference OWASP, RFCs, CWE, or W3C specifications — not internal opinions. See [Standards & References](./docs/standards.md) for the full per-rule mapping.

**150 tests, all passing.** Every rule is tested against both a vulnerable and a secure implementation before release. See [How We Ensure Accuracy](./docs/accuracy.md) for the testing methodology and false-positive strategy.

**Rules are documented with rationale.** Every rule in [`docs/rules/`](./docs/rules/) includes a description, a vulnerable example, a secure example, the security impact, and references to OWASP, RFCs, or official documentation — so you understand *why* a finding matters, not just *that* it fired.

## Why express-audit?

Dependency scanners tell you about CVEs in packages you installed. express-audit tells you about security mistakes in code you wrote.

Those are different problems. A dependency scanner won't tell you that your `jwt.sign()` call has no expiry, that your session secret is hardcoded, or that `cors()` is called without an origin allowlist. Those are application-level misconfigurations — and they're the ones that show up in bug bounty reports and breach postmortems.

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

## How it's different

**It understands many common Express APIs and configuration patterns.** Rules are written against `res.cookie()`, `jwt.sign()`, `session()`, and `cors()` specifically. A generic linter sees function calls. express-audit sees a cookie being set without `httpOnly`, a JWT being signed without `expiresIn`, or a session being configured with a hardcoded secret — and flags the specific option that's missing or wrong. Not every API or configuration style is covered, but the most common patterns are.

**It analyzes supported Express routing and middleware patterns.** For common patterns — `router.delete('/users/:id', handler)` with no middleware argument, or `app.use(cors())` with no options — it can identify what's absent. It works at the AST level on what is written in a single file. It does not perform cross-file data flow analysis, cannot follow middleware registered through factories or dependency injection, and will miss patterns it wasn't written to recognise. False negatives are possible; the tool is conservative to keep false positives low.

**Every finding is actionable.** File path, line number, security impact, and a concrete fix — in every report.

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

## Why not Semgrep?

Semgrep is a capable tool and express-audit doesn't replace it. If you already use Semgrep, keep using it.

The practical difference is setup cost. Semgrep ships with a large rule registry, but Express-specific security rules — "jwt.sign without expiresIn", "session with a hardcoded secret", "cors() defaulting to wildcard" — aren't there out of the box. You'd need to author, test, and maintain them yourself.

express-audit provides batteries-included Express-specific rules without requiring users to author Semgrep patterns. Run it with zero configuration, get findings specific to Express, and move on.

**They can coexist.** Semgrep is strong for cross-language scanning and custom taint rules you own. express-audit is narrow but ready to run immediately on any Express project. Run both if you use Semgrep — they don't overlap meaningfully.

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

## Example Output

Real output from running `express-audit` against the bundled [vulnerable example app](./examples/vulnerable-app/app.js).

```
Express Audit v0.1.12

📊 Security Score: 79/100

The score is a weighted heuristic. A score of 100 does not mean the application
is secure; a low score does not mean it is insecure. Use it to track progress
and prioritise fixes.

🔴 Critical (7)
────────────────────────────────────────────────────────────
JWT001 | Hardcoded JWT Secret
Location: app.js:34
Impact:   Hardcoded secrets can be extracted from source code, allowing
          attackers to forge valid JWT tokens and impersonate users.
Fix:      Use environment variables: jwt.sign(payload, process.env.JWT_SECRET)

AUTH002 | Plaintext Password Comparison
Location: app.js:67
Impact:   Storing or comparing plaintext passwords allows credential theft
          from database breaches.
Fix:      Use: await bcrypt.compare(inputPassword, storedHash)

SESSION001 | Hardcoded Session Secret
Location: app.js:21
Impact:   Hardcoded secrets can be extracted from source, allowing session forgery.
Fix:      Use: secret: process.env.SESSION_SECRET

SQL001 | SQL Injection via Template Literal
Location: app.js:49
Impact:   Attackers can inject arbitrary SQL, leading to data theft,
          modification, or database destruction.
Fix:      Use parameterized queries: db.query("SELECT ... WHERE id = ?", [userInput])

AUTHZ002 | Admin Route Unprotected
Location: app.js:54
Impact:   Unprotected admin routes can be accessed by any user.
Fix:      router.get("/admin/users", authenticate, requireRole("admin"), handler)

DOCKER004 | Secrets in Dockerfile
Location: Dockerfile:10
Impact:   Secrets embedded in Docker images can be extracted from image layers.
Fix:      Pass secrets at runtime via environment variables or Docker secrets

⚠️  High (8)
────────────────────────────────────────────────────────────
JWT002 | JWT Missing Expiration
AUTH001 | Weak bcrypt Cost Factor
AUTHZ001 | Sensitive Route Missing Authentication
HTTP001 | Helmet Middleware Missing
COOKIE001 | Cookie Missing Security Options
CORS001 | CORS Allows All Origins
SECRET008 | Hardcoded Password in Variable
DOCKER001 | Container Running as Root

📋 Medium (5)
────────────────────────────────────────────────────────────
CSP001 | Missing Content Security Policy
SESSION001 | Session saveUninitialized Should Be False
RATE001 | No Rate Limiting Detected
PROD003 | Missing Trust Proxy Configuration
DOCKER002 | Using Latest Tag

ℹ️  Low (7)
────────────────────────────────────────────────────────────
HEADER001 | X-Powered-By Header Enabled
PROD001 | Missing Health Check Endpoint
PROD002 | Missing Graceful Shutdown
PROD004 | Compression Middleware Missing
DOCKER003 | Missing HEALTHCHECK
DOCKER005 | COPY . . in Dockerfile

📈 Category Scores
────────────────────────────────────────────────────────────
Authentication             30% ██████░░░░░░░░░░░░░░
Docker                     31% ██████░░░░░░░░░░░░░░
Authorization              65% █████████████░░░░░░░
Sessions                   68% █████████████░░░░░░░
SQL Security               75% ███████████████░░░░░
HTTP Security              83% ████████████████░░░░
Production Readiness       89% █████████████████░░░
Cookies                    90% ██████████████████░░
CORS                       90% ██████████████████░░
Rate Limiting              95% ███████████████████░
Input Validation          100% ████████████████████
Logging                   100% ████████████████████
OAuth                     100% ████████████████████

Summary
------------------------------------------------------------
Total files scanned:  2
Total findings:      27
Critical:             7
High:                 8
Medium:               5
Low:                  7
```

After applying the fixes shown in [Real-World Examples](./docs/examples.md), the same project scores **100/100 with 0 findings**.

## Documentation

| Document | Description |
|---|---|
| [How We Ensure Accuracy](./docs/accuracy.md) | Why AST over regex, how false positives are minimised, what the tool intentionally does not report |
| [False Positives & False Negatives](./docs/false-positives.md) | Per-rule documentation of where the tool may over-report or under-report, and why |
| [Real-World Examples](./docs/examples.md) | Vulnerable code → finding → fix → no finding, for five common rules |
| [Standards & References](./docs/standards.md) | Per-rule mapping to OWASP, RFCs, CWE, and W3C specifications |
| [Rule Reference](./docs/rules/README.md) | All rules with severity, category, and documentation links |
| [Security Policy](./SECURITY.md) | Vulnerability reporting, responsible disclosure, supported versions |
| [Contributing](./CONTRIBUTING.md) | How to write rules, tests, and documentation |

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
Passwords, tokens, and API keys written to log output; full request body logging; stack traces returned to clients. Sensitive fields (`api_key`, `secret`, `password`, `access_token`) returned directly in HTTP response bodies.

### Error Handling
Raw error objects returned in HTTP responses, missing global error-handler middleware.

### Performance
Database queries executed inside loops (N+1 queries) — detects `await prisma.findUnique()`, `await db.query()`, and equivalent calls inside `for`, `forEach`, `map`, and `while` constructs across Prisma, Mongoose, Sequelize, TypeORM, and raw drivers.

### OAuth Security & Google CASA Readiness
Missing PKCE, state parameter validation, and nonce validation; overly broad OAuth scopes; unencrypted refresh token storage; missing token revocation.

> express-audit covers only the portions of Google CASA that can reasonably be verified through static analysis — things like missing PKCE, unencrypted token storage patterns, and absent state validation. The majority of a CASA assessment involves organizational controls, infrastructure review, penetration testing, and runtime behaviour that no static tool can evaluate.

### Production Readiness
Missing health check endpoints, graceful shutdown handlers, trust proxy configuration, and compression middleware.

### Docker
Container running as root, `:latest` image tags, missing `HEALTHCHECK`, secrets baked into the image, and `COPY . .` without a `.dockerignore`.

## Rule Reference

Dozens of built-in rules across 16 categories. Full documentation for each rule — including vulnerable examples, secure examples, and remediation steps — is in [`docs/rules/`](./docs/rules/).

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
| `LOG`, `SEC` | Logging & Response Security | LOG001–LOG003, SEC001 |
| `ERR` | Error Handling | ERR001, ERR002 |
| `OAUTH` | OAuth Security | OAUTH001, OAUTH002, OAUTH003 |
| `CASA` | Google CASA Readiness | CASA001–CASA005 |
| `PROD` | Production Readiness | PROD001–PROD004 |
| `DOCKER` | Docker | DOCKER001–DOCKER005 |
| `PERF` | Performance | PERF001 |

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
  rules/              — growing rule library across 16 categories

tests/                — unit and integration tests
docs/rules/           — Per-rule documentation
examples/             — Vulnerable and secure Express apps
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to write a rule, what tests are required, and the PR process.

## Roadmap

- [ ] NestJS, Fastify, Hono, and Koa support via framework adapters
- [ ] VS Code extension
- [ ] Custom rule SDK with a plugin entry point
- [ ] Baseline files — suppress known findings, surface only new ones
- [ ] GitLab CI template

## License

MIT © 2026
