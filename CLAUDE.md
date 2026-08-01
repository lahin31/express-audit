# CLAUDE.md

This file gives Claude (and other AI coding assistants) the context needed to work
accurately on express-audit without exploring the codebase from scratch.

---

## What this project is

express-audit is a static security analysis CLI for Express.js applications. It parses
source files into an AST using `@babel/parser`, runs structured rule visitors over the
tree, and reports findings with file path, line number, severity, impact, and fix.

It does not execute application code, make network requests, or write to the project
being scanned.

---

## Commands

```bash
# Install dependencies
npm install

# Generate the version file (required before build or test)
node scripts/generate-version.mjs

# Build TypeScript to dist/
npm run build

# Run all tests (150 tests across 15 files)
npm test

# Run tests in watch mode
npm run test:watch

# Lint
npm run lint

# Run the CLI against the bundled example apps
node dist/cli.js examples/vulnerable-app
node dist/cli.js examples/secure-app

# Run against a specific subdirectory
node dist/cli.js ./src
```

`npm test` will fail with "Cannot find module ../version.js" if
`node scripts/generate-version.mjs` has not been run first. The `prebuild` script runs
it automatically before `npm run build`.

---

## Project structure

```
src/
  cli.ts                   CLI entry point (Commander.js)
  index.ts                 Public programmatic API
  version.ts               Auto-generated — do not edit by hand
  core/
    engine.ts              Discovers files, runs rules, calculates scores
    ast-helpers.ts         Shared Babel AST utilities (traverse, getStringValue, etc.)
    config-loader.ts       Finds and merges express-audit.config.js
    is-entry-file.ts       Detects app.js / server.js / index.ts entry files
    remediation.ts         bothStyles() helper for ESM+CJS remediation snippets
  parser/
    index.ts               Babel parser wrapper with TypeScript + JSX plugin set
  reporters/
    cli-reporter.ts        Coloured terminal output
    json-reporter.ts       Machine-readable JSON
    html-reporter.ts       Self-contained HTML report
    sarif-reporter.ts      SARIF for GitHub Code Scanning
  rules/
    index.ts               Aggregates all rule arrays into allRules[]
    <category>/
      <rule-name>.ts       Individual rule implementation
      index.ts             Exports rule array for the category
  types/
    index.ts               All shared TypeScript types

tests/
  helpers.ts               createContext() and createContextFromFixture()
  engine.test.ts           Integration tests (scans examples/ apps)
  reporters.test.ts        Reporter output tests
  rules/
    *.test.ts              Per-category unit tests

docs/
  accuracy.md              How AST analysis works, false-positive strategy
  examples.md              Vulnerable → finding → fix → no finding walkthroughs
  false-positives.md       Per-rule false positive and false negative documentation
  standards.md             Per-rule OWASP / RFC / CWE reference tables
  rules/                   Per-rule documentation pages

examples/
  vulnerable-app/app.js    Intentionally insecure Express app (used in engine tests)
  secure-app/app.js        Well-secured Express app
```

---

## Core types

```typescript
// A rule returns Finding[] from run(context: RuleContext)
interface Rule {
  id: string;               // e.g. 'JWT001'
  severity: Severity;       // 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: string;         // must match a key in CATEGORY_WEIGHTS
  title: string;
  description: string;
  detectorType: DetectorType; // 'ast' | 'regex' | 'file' | 'config' | 'dependency'
  references: RuleReference[];
  remediation: string;
  run(context: RuleContext): Finding[];
}

interface RuleContext {
  filePath: string;
  source: string;           // raw file content
  ast?: unknown;            // Babel File node, cast to File in rules
  projectRoot: string;
  allFiles: string[];       // every file in the scanned directory
  config: AuditConfig;
}

interface Finding {
  ruleId: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;      // what was found
  impact: string;           // why it matters
  remediation: string;      // how to fix this specific instance
  references: RuleReference[];
  filePath?: string;
  line?: number;
  column?: number;
  snippet?: string;
}
```

---

## How to write a rule

1. Create `src/rules/<category>/<descriptive-name>.ts`
2. Export a `const myRule: Rule = { ... }` object
3. Add it to `src/rules/<category>/index.ts` and the category array
4. The category name must exactly match a key in `CATEGORY_WEIGHTS` in `src/types/index.ts`

Minimal rule skeleton:

```typescript
import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

export const myRule: Rule = {
  id: 'CAT001',
  severity: 'high',
  category: 'Authentication',   // must match CATEGORY_WEIGHTS key
  title: 'Short title',
  description: 'What this rule detects.',
  detectorType: 'ast',
  remediation: 'How to fix it.',
  references: [
    { title: 'OWASP ...', url: 'https://owasp.org/...' },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];
    const findings: Finding[] = [];
    const ast = context.ast as File;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        // detection logic
        findings.push({
          ruleId: 'CAT001',
          severity: 'high',
          category: 'Authentication',
          title: 'Short title',
          description: 'What was found.',
          impact: 'What an attacker can do.',
          remediation: 'Specific fix.',
          references: myRule.references,
          filePath: context.filePath,
          line: getNodeLine(path.node),
        });
      },
    });

    return findings;
  },
};
```

---

## Key AST helpers (`src/core/ast-helpers.ts`)

| Helper | What it does |
|---|---|
| `traverse(ast, visitors)` | Walk the AST with Babel visitor pattern |
| `getStringValue(node)` | Returns string from `StringLiteral` or static `TemplateLiteral`, else `null` |
| `isProcessEnv(node)` | Returns `true` if node is `process.env.SOMETHING` |
| `getObjectProperty(obj, key)` | Gets a property value from an `ObjectExpression` |
| `isBoolFalse(node)` / `isBoolTrue(node)` | Checks boolean literal value |
| `findImports(ast, pkg)` | Checks if a package is imported or required anywhere in the file |
| `getNodeLine(node)` | Line number from AST node |
| `getNodeColumn(node)` | Column number from AST node |
| `getCalleeName(call)` | Returns `"obj.method"` string from a call expression |

---

## Key design decisions

**Entry-file scoping.** Project-level rules (HTTP001, CSP001, RATE001, HEADER001, ERR002)
only fire from entry files (`app.js`, `server.js`, `main.js`, `index.js` at root or one
level deep with Express signals). They also scan `context.allFiles` before reporting —
e.g. HTTP001 scans every file for a helmet import before concluding it is missing.

**isEntryFile criteria:** filename is one of the known names + depth ≤ 2 + source contains
`express()`, `app.use(`, `app.listen`, `app.get(`, `app.post(`, or `createServer`.

**False-positive preference.** If a rule cannot confirm a vulnerability with high
confidence, it returns `[]`. No speculative findings.

**No data-flow analysis.** Rules inspect call sites directly. Secrets assigned to
variables before being passed to `jwt.sign()` are not traced. This is a known limitation
documented in `docs/false-positives.md`.

**`.env` files are never scanned.** Hard-excluded in both the glob patterns and a
post-discovery filter in `engine.ts`.

**`bothStyles(pkg, identifier, usage, named?)`** in `src/core/remediation.ts` generates
remediation strings showing both ESM and CJS import patterns. Use it for any rule that
recommends installing a package.

---

## How to write tests

Tests use Vitest. Test helpers are in `tests/helpers.ts`.

```typescript
import { describe, it, expect } from 'vitest';
import { myRule } from '../../src/rules/authentication/my-rule.js';
import { createContext, createContextFromFixture } from '../helpers.js';

describe('CAT001 – short title', () => {
  it('flags the vulnerable pattern', () => {
    const ctx = createContext(`jwt.sign(payload, 'hardcoded')`);
    const findings = myRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('CAT001');
  });

  it('does not flag the secure pattern', () => {
    const ctx = createContext(`jwt.sign(payload, process.env.SECRET)`);
    expect(myRule.run(ctx)).toHaveLength(0);
  });
});
```

**`createContext(source, fileName?)`** — writes source to a temp file, parses it, returns
`RuleContext`. Default filename does not trigger entry-file checks.

**`createContextFromFixture(source, fixtureName)`** — same, but sets `filePath` to the
fixture name so path-based rules (e.g. `'app.js'`, `'Dockerfile'`) behave correctly.

Every rule must have at minimum one test that fires (true positive) and one that does not
(false positive check).

---

## Rule ID registry

| Prefix | Category | Used |
|---|---|---|
| `JWT` | Authentication – JWT | 001–002 |
| `AUTH` | Authentication | 001–002 |
| `AUTHZ` | Authorization | 001–002 |
| `VAL` | Input Validation | 001–002 |
| `SQL` | SQL Security | 001–002 |
| `HTTP` | HTTP Security | 001 |
| `HEADER` | HTTP Headers | 001 |
| `CSP` | Content Security Policy | 001 |
| `COOKIE` | Cookies | 001 |
| `SESSION` | Sessions | 001 |
| `CORS` | CORS | 001 |
| `RATE` | Rate Limiting | 001 |
| `SECRET` | Secrets | 001–010 |
| `LOG` | Logging | 001–003 |
| `SEC` | Response Security | 001 |
| `ERR` | Error Handling | 001–002 |
| `OAUTH` | OAuth | 001–003 |
| `CASA` | Google CASA Readiness | 001–005 |
| `PROD` | Production Readiness | 001–004 |
| `DOCKER` | Docker | 001–005 |
| `PERF` | Performance | 001 |

Pick the next available number in the appropriate prefix range.

---

## Scoring

- Each category starts at 100 points
- Deductions per finding: critical −25, high −10, medium −5, low −2, info −0
- Overall score is a weighted average across categories (weights in `CATEGORY_WEIGHTS`)
- Score of 100 means no findings — it does not mean the app is secure

---

## Dependencies (runtime only)

| Package | Purpose |
|---|---|
| `@babel/parser` | Parse JS/TS into AST |
| `@babel/traverse` | Walk AST nodes |
| `@babel/types` | AST node type guards |
| `chalk` | Terminal colours |
| `commander` | CLI argument parsing |
| `glob` | File discovery |
| `yaml` | Parse docker-compose files |

No network access. No telemetry. No execution of scanned code.
