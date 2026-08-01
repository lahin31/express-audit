# How express-audit Ensures Accuracy

express-audit deliberately favors fewer false positives over maximum detection coverage.
If a rule cannot determine with high confidence that a vulnerability exists, it does not report a finding.
This document explains how that principle is put into practice.

---

## Why AST Instead of Regex

Most rules in express-audit analyze code by building and traversing an Abstract Syntax Tree (AST)
rather than matching raw text with regular expressions.

The difference matters in practice.

A regex looking for `jwt.sign` would fire on a comment, a string inside a test fixture, or a
variable named `_mockJwtSign`. An AST-based check walks the actual parse tree and only matches
a real `CallExpression` whose callee is a `MemberExpression` with object `jwt` and method `sign`.
It can then inspect the exact second argument node — and only flag it if that argument is a
`StringLiteral` (a hardcoded value) rather than a `MemberExpression` pointing at `process.env`.

The parser used is `@babel/parser` with a broad plugin set that covers TypeScript, JSX, decorators,
optional chaining, nullish coalescing, and more. When TypeScript parsing fails it automatically
retries with plain JavaScript plugins, so polyglot projects are handled without manual
configuration. Files larger than 2 MB are skipped entirely rather than parsed partially —
partial parses produce unreliable ASTs and would increase false positives.

Regex is used only where it is the right tool: scanning for high-entropy, structurally unique
credential patterns (AWS Access Key IDs, Stripe secret keys, PEM headers, database URLs) that
would be cumbersome to match via an AST walk. Those patterns are chosen to be as specific as
possible — for example, AWS key detection looks for the literal prefix `AKIA` followed by exactly
sixteen uppercase alphanumeric characters, not a generic "looks long" heuristic.

---

## How Rules Are Tested

Rules are tested with [Vitest](https://vitest.dev/) (`npm test`).

Each rule has unit tests that cover:

- **True positives** — code that contains the exact vulnerability the rule targets.
  The test asserts that at least one finding is returned, with the expected `ruleId`, `severity`,
  and line number.
- **True negatives** — correct code that should produce no findings.
  For example, `jwt.sign(payload, process.env.JWT_SECRET)` must return zero findings from JWT001,
  and `bcrypt.hash(password, 12)` must return zero findings from AUTH001.
- **Edge cases** — missing arguments, non-standard variable names, alternative import styles
  (`require` vs `import`), and equivalent patterns that should or should not trigger.

The CI pipeline (`.github/workflows/ci.yml`) runs the full test suite on every push and pull
request, ensuring regressions are caught before a release reaches users.

---

## How False Positives Are Minimized

Several concrete techniques are applied across the rule set.

**Checking what the value actually is, not just whether it exists.**
`JWT001` only flags a JWT secret when it is provably a `StringLiteral` or a static
`TemplateLiteral` (no expressions). If the secret comes from `process.env`, a variable, or a
function call, the rule stays silent — it cannot prove the value is hardcoded.

**Distinguishing the argument position.**
`AUTH001` checks only the second argument to `bcrypt.hash()` / `bcrypt.hashSync()` — the salt
rounds — not the first (the password). The rule flags when that argument is a numeric literal
below 12, and stays silent when it is a variable or constant whose value cannot be known at
parse time.

**Entry-file scoping for project-level checks.**
`HTTP001` (Helmet missing) only fires on the application entry file — a file whose name is one
of `app`, `server`, `main`, or `index`, sitting at the project root or one directory deep, and
whose source contains evidence of Express setup (`express()`, `app.use(`, etc.). Before
reporting, the rule scans every other file in the project for a `helmet` import. If helmet is
imported in any file — even a dedicated middleware setup file deep in `src/` — no finding is
raised. This prevents false positives on projects that initialize middleware outside of their
entry point.

**Auth middleware heuristics designed to recognize custom names.**
`AUTHZ001` maintains a list of known authentication middleware names, but also applies a textual
heuristic: if a middleware's identifier appears in source code that accesses `req.user`,
`authorization` headers, Bearer tokens, or JWT decoded values, it is treated as auth middleware
even when its name is something like `validateAdminAccess`. This substantially reduces false
positives on codebases that do not use the standard naming conventions.

**SQL injection requires both a query call and traceable user input.**
`SQL001` only flags string concatenation or template literals passed to `.query()`, `.execute()`,
or `.run()` when those strings provably contain a reference to `req.body`, `req.query`,
`req.params`, or `req.headers`. A query built from two hardcoded string fragments is not flagged,
because there is no user input in the picture.

**Skipping files that are expected to contain patterns.**
The secrets scanner skips files whose basename includes `fixture`, `mock`, or `spec`, and
unconditionally skips any file whose name starts with or ends in `.env` — those files are expected
to hold credential-shaped values. The engine also hard-excludes `.env.*` files from the file
discovery step, so they are never scanned regardless of which rule runs.

**Comments are not scanned for secrets.**
Lines that begin with `//`, `#`, or `*` are skipped by the secrets scanner, so example keys in
documentation comments do not generate findings.

---

## When the Tool Intentionally Does Not Report a Finding

express-audit stays silent in the following situations by design.

| Situation | Reason |
|---|---|
| A JWT secret comes from `process.env` | The value is not known at parse time; no confidence it is insecure |
| Helmet is imported anywhere in the project | The project-wide scan confirms it is in use |
| An auth middleware uses a custom name but its body reads `req.user` or checks `authorization` | Source heuristics provide enough signal to classify it as auth middleware |
| A file is named `*.spec.ts`, `*.mock.js`, or contains `fixture` in its name | Test fixtures intentionally contain credential-shaped strings |
| The AST cannot be built (parse error, file > 2 MB) | Partial analysis would produce unreliable results |
| A rule is explicitly disabled in `express-audit.config.js` | The user has opted out of that check |
| A path matches an `ignore.paths` pattern in the config | The user has excluded that path from analysis |
| `process.env` is present anywhere on a line being scanned for secrets | Strong signal the value is environment-sourced |

---

## Current Limitations

**No data-flow analysis.**
express-audit performs syntactic analysis, not data-flow or taint analysis. It inspects structure
and literal values at the call site. If a hardcoded secret is assigned to a variable ten lines
before being passed to `jwt.sign()`, the rule sees a variable reference at the call site and
stays silent — it cannot trace the assignment chain. A dedicated data-flow tool such as Semgrep
or CodeQL handles those cases.

**No cross-file analysis for most rules.**
Rules generally operate on one file at a time. Whether a function defined in
`auth/middleware.js` is actually called on a route in `routes/users.js` is not verified — with
the exception of project-level checks like Helmet detection, which do scan all files.

**Indirect require/import patterns are not resolved.**
Dynamic imports (`require(varName)`) and computed property access on module objects are not
resolved. The tool only recognizes direct `import 'x'` statements and `require('x')` calls with
a string literal argument.

**Template literals with variables are not evaluated.**
If a JWT secret is built from a template literal that contains an expression — even one as simple
as `` `${hardcoded}` `` — `getStringValue()` returns `null` and the check does not fire.

**Runtime configuration is invisible.**
Settings applied at runtime (environment variables resolved by a config service, secrets injected
by Kubernetes, feature flags) are not visible to a static tool. A route may be protected at
runtime by middleware that is conditionally registered, but the static check will not see that.

**CASA checks cover only static-analysis-verifiable items.**
Google CASA requires organizational controls, infrastructure review, and penetration testing that
no static tool can perform. The CASA rules in express-audit cover only the subset that can be
confirmed from source code. All audit results include an explicit note to this effect.

**Docker and YAML analysis is line-based.**
Dockerfile and `docker-compose` scanning does not use a full YAML or Dockerfile AST. It uses
structured line and pattern matching, which is accurate for common patterns but may miss
multi-line constructs or unusual formatting.

---

## What the Tool Cannot Detect

The following classes of vulnerability are outside the scope of express-audit.

- **Runtime injection attacks** — XSS payloads, SSRF, OS command injection through `child_process`
  with dynamic arguments, and prototype pollution that depend on the shape of live request data.
- **Insecure dependencies** — known CVEs in npm packages. Use `npm audit` or a dedicated SCA
  tool (Snyk, Dependabot) for that.
- **Logic flaws** — business logic vulnerabilities such as incorrect access control between roles,
  IDOR through predictable IDs, or race conditions are not detectable through pattern matching.
- **Infrastructure misconfigurations** — TLS certificate validity, network ACLs, cloud IAM policies,
  and database firewall rules are outside the scope of application-level static analysis.
- **Secrets already in version control history** — the tool scans the current working tree.
  Secrets committed in earlier commits and then removed are not surfaced. Use `git-secrets` or
  `trufflehog` for history scanning.
- **Encrypted or obfuscated code** — minified bundles and obfuscated source are excluded from
  analysis (`dist/` and `build/` directories are skipped by default).
- **Authentication at the infrastructure layer** — API gateway authentication, reverse proxy
  access controls (Nginx, Caddy), and service mesh mTLS are not visible at the Express layer.

---

## Summary

| Property | Approach |
|---|---|
| Primary analysis method | Babel AST traversal |
| Supplementary method | Targeted regex for structured credential patterns |
| False positive strategy | Silence when confidence is below threshold |
| Test framework | Vitest, run on every CI push |
| Scope | Single-project, source-code only |
| Files intentionally skipped | `node_modules`, `dist`, `build`, `.env*`, test fixtures, files > 2 MB |
| Runtime / data-flow analysis | Not supported — use Semgrep or CodeQL for those cases |

Security engineers: if you find a false positive or a missed true positive, open an issue at
[https://github.com/JSExplore/express-audit/issues](https://github.com/JSExplore/express-audit/issues).
Accurate rules are more useful than comprehensive ones.
