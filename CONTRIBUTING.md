# Contributing to express-audit

Thank you for helping make Express.js applications more secure. This guide covers
everything you need to contribute rules, fixes, documentation, or infrastructure
improvements.

---

## Table of Contents

1. [Development Setup](#development-setup)
2. [Project Structure](#project-structure)
3. [Writing a New Rule](#writing-a-new-rule)
4. [Writing Tests](#writing-tests)
5. [Writing Rule Documentation](#writing-rule-documentation)
6. [Pull Request Process](#pull-request-process)
7. [Rule ID Allocation](#rule-id-allocation)
8. [Code Style](#code-style)
9. [Reporting Security Issues](#reporting-security-issues)

---

## Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/express-audit.git
cd express-audit

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run tests in watch mode during development
npm run test:watch

# Lint
npm run lint

# Smoke-test the CLI against the example apps
node dist/cli.js examples/vulnerable-app
node dist/cli.js examples/secure-app
```

Node.js **18 or higher** is required.

---

## Project Structure

```
src/
  cli.ts              — CLI entry point (Commander.js)
  index.ts            — Public programmatic API
  core/
    engine.ts         — Rule runner and scoring engine
    ast-helpers.ts    — Shared Babel AST utilities
    config-loader.ts  — Config file discovery and merging
  parser/
    index.ts          — Babel parser wrapper
  reporters/
    cli-reporter.ts   — Coloured terminal output
    json-reporter.ts  — Machine-readable JSON
    html-reporter.ts  — Self-contained HTML report
    sarif-reporter.ts — SARIF for GitHub Code Scanning
  rules/
    <category>/
      <rule-name>.ts  — Individual rule implementation
      index.ts        — Re-exports and category array
  types/
    index.ts          — All shared TypeScript types

tests/
  helpers.ts          — Test utilities (createContext, createContextFromFixture)
  engine.test.ts      — Integration tests for the audit engine
  reporters.test.ts   — Reporter output tests
  rules/
    *.test.ts         — Per-category unit tests

docs/
  rules/
    <RULE_ID>.md      — Documentation page for each rule
    README.md         — Rule reference index

examples/
  vulnerable-app/     — Intentionally insecure Express app (used in engine tests)
  secure-app/         — Example of well-secured Express app
```

---

## Writing a New Rule

Every rule is a single TypeScript file that exports an object implementing the
`Rule` interface. Rules are completely independent — they receive a `RuleContext`
and return an array of `Finding` objects.

### 1. Choose a category and pick an ID

See [Rule ID Allocation](#rule-id-allocation) below.

### 2. Create the rule file

```
src/rules/<category>/<descriptive-name>.ts
```

```typescript
import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

export const myNewRule: Rule = {
  id: 'CAT001',                        // Unique rule ID
  severity: 'high',                    // critical | high | medium | low | info
  category: 'Authentication',          // Must match a key in CATEGORY_WEIGHTS
  title: 'Short Human-Readable Title',
  description: 'One-sentence description of what this rule detects.',
  detectorType: 'ast',                 // ast | regex | file | config | dependency
  remediation: 'How to fix the issue.',
  references: [
    {
      title: 'OWASP — Relevant Page',
      url: 'https://owasp.org/...',
    },
  ],

  run(context: RuleContext): Finding[] {
    // Rules that only check specific file types should return early
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        // ... detect the pattern
        if (/* vulnerable pattern found */) {
          findings.push({
            ruleId: 'CAT001',
            severity: 'high',
            category: 'Authentication',
            title: 'Short Human-Readable Title',
            description: 'What was found and where.',
            impact: 'What an attacker can do with this.',
            remediation: 'Specific fix for this instance.',
            references: myNewRule.references,
            filePath: context.filePath,
            line: getNodeLine(path.node),
          });
        }
      },
    });

    return findings;
  },
};
```

### 3. Register the rule

Add it to `src/rules/<category>/index.ts`:

```typescript
export { myNewRule } from './my-new-rule.js';

import { myNewRule } from './my-new-rule.js';
import type { Rule } from '../../types/index.js';

export const authenticationRules: Rule[] = [
  // existing rules...
  myNewRule,  // add here
];
```

### AST Helper Reference

`src/core/ast-helpers.ts` exports commonly-needed helpers:

| Helper | Purpose |
|---|---|
| `traverse(ast, visitors)` | Walk the AST |
| `getStringValue(node)` | Get string from `StringLiteral` or simple `TemplateLiteral` |
| `isProcessEnv(node)` | Check if node is `process.env.X` |
| `getObjectProperty(obj, key)` | Get a property value from an `ObjectExpression` |
| `isBoolFalse(node)` / `isBoolTrue(node)` | Check boolean literal value |
| `findImports(ast, pkg)` | Check if a package is imported/required |
| `getNodeLine(node)` | Get line number from AST node |
| `getCalleeName(call)` | Get `"obj.method"` string from a call expression |

### Rule Design Principles

- **Low false-positive rate first.** An audit tool that cries wolf gets disabled.
- **Return early** for files / patterns that clearly don't apply.
- **Limit findings per file** if the same issue repeats — return at most 3 per file to avoid noise.
- **Never execute** any application code.
- **Include line numbers** whenever available.
- **Be specific** in `description` (what was found) vs `impact` (why it matters) vs `remediation` (how to fix).

---

## Writing Tests

Tests live in `tests/rules/<category>.test.ts`. Use `vitest` with the helpers in
`tests/helpers.ts`.

```typescript
import { describe, it, expect } from 'vitest';
import { myNewRule } from '../../src/rules/authentication/my-new-rule.js';
import { createContext, createContextFromFixture } from '../helpers.js';

describe('CAT001 – Short title', () => {
  // Test that the rule fires on a vulnerable pattern
  it('flags the vulnerable pattern', () => {
    const ctx = createContext(`
      // source code with the vulnerability
    `);
    const findings = myNewRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('CAT001');
    expect(findings[0].severity).toBe('high');
  });

  // Test that the rule does NOT fire on the secure pattern (no false positives)
  it('does not flag the secure pattern', () => {
    const ctx = createContext(`
      // source code without the vulnerability
    `);
    expect(myNewRule.run(ctx)).toHaveLength(0);
  });
});
```

**`createContext(source, fileName?)`** — creates a temporary file with the given
source. The default filename does not match any entry-file check. Use a specific
filename when rules inspect the path (e.g. `'app.js'`, `'Dockerfile'`).

**`createContextFromFixture(source, fixtureName)`** — same but the `filePath` in
the returned context is set to the fixture name, so path-checking rules behave
correctly without creating subdirectories.

Every rule must have at minimum:
- One test that **fires** (true positive)
- One test that **does not fire** (false positive check)

---

## Writing Rule Documentation

Create `docs/rules/<RULE_ID>.md` using this template:

```markdown
# RULE_ID — Rule Title

| Property     | Value         |
|--------------|---------------|
| **ID**       | RULE_ID       |
| **Severity** | 🔴 Critical   |
| **Category** | Category Name |
| **Detector** | AST           |

## Description
One paragraph explaining what the rule detects.

## Why It Matters
Why this is a security issue. Be specific about the attack class.

## Vulnerable Example
\`\`\`typescript
// ❌ Annotated bad code
\`\`\`

## Secure Example
\`\`\`typescript
// ✅ Annotated good code
\`\`\`

## Remediation
Numbered steps.

## References
- [Title](url)
```

Then add it to the table in `docs/rules/README.md`.

---

## Pull Request Process

1. **Fork** the repository and create a branch: `git checkout -b feat/CAT001-my-rule`
2. **Write the rule**, tests, and documentation together.
3. Ensure `npm test` passes with 0 failures.
4. Ensure `npm run build` succeeds with no TypeScript errors.
5. Run `node dist/cli.js examples/vulnerable-app` — confirm your rule fires where expected.
6. Open a PR against `main` with:
   - A clear description of the vulnerability being detected
   - The rule ID and category
   - False-positive rate assessment (what patterns were considered and excluded)
   - References to the relevant OWASP/CWE/RFC pages

### PR Title Format

```
feat(rules): add CAT001 – Short Rule Title
fix(rules): reduce false positives in SQL001
docs(rules): add documentation for AUTH002
chore: update dependencies
```

---

## Rule ID Allocation

| Prefix | Category | Current range |
|---|---|---|
| `JWT` | Authentication – JWT | 001–010 |
| `AUTH` | Authentication – General | 001–010 |
| `AUTHZ` | Authorization | 001–010 |
| `VAL` | Input Validation | 001–010 |
| `SQL` | SQL Security | 001–010 |
| `HTTP` | HTTP Security | 001–010 |
| `HEADER` | HTTP Headers | 001–010 |
| `CSP` | Content Security Policy | 001–005 |
| `COOKIE` | Cookies | 001–010 |
| `SESSION` | Sessions | 001–010 |
| `CORS` | CORS | 001–010 |
| `RATE` | Rate Limiting | 001–010 |
| `SECRET` | Secrets | 001–010 |
| `LOG` | Logging | 001–010 |
| `ERR` | Error Handling | 001–010 |
| `OAUTH` | OAuth | 001–010 |
| `CASA` | Google CASA Readiness | 001–010 |
| `PROD` | Production Readiness | 001–010 |
| `DOCKER` | Docker | 001–010 |

Pick the next available number in the appropriate range. If adding a new category,
propose a prefix in your PR.

---

## Code Style

- TypeScript strict mode — no `any` without justification.
- ES modules throughout (`import`/`export`, `.js` extensions in imports).
- No external runtime dependencies beyond what is already in `package.json`.
- Rules must not `console.log` — use `return []` to skip silently.
- Prefer `const` over `let`; no `var`.

The project uses ESLint. Run `npm run lint` before submitting.

---

## Reporting Security Issues

Please **do not** open a public GitHub issue for security vulnerabilities in
`express-audit` itself. Instead, email `security@yourdomain.com` with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact

We aim to respond within 48 hours and will coordinate a fix + disclosure timeline
with you.
