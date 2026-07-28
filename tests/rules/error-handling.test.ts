import { describe, it, expect } from 'vitest';
import { rawErrorResponseRule, missingErrorHandlerRule } from '../../src/rules/error-handling/error-handling.js';
import { createContext, createContextFromFixture } from '../helpers.js';

describe('ERR001 – Raw error returned to client', () => {
  it('flags res.json(err)', () => {
    const ctx = createContext(`res.json(err);`);
    const findings = rawErrorResponseRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('ERR001');
  });

  it('flags res.send(error)', () => {
    const ctx = createContext(`res.send(error);`);
    expect(rawErrorResponseRule.run(ctx)).toHaveLength(1);
  });

  it('flags res.json({ stack: err.stack })', () => {
    const ctx = createContext(`res.json({ message: err.message, stack: err.stack });`);
    expect(rawErrorResponseRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag res.json({ error: "safe message" })', () => {
    const ctx = createContext(`res.json({ error: 'Internal server error' });`);
    expect(rawErrorResponseRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag res.json(data) where data is not an error variable', () => {
    const ctx = createContext(`res.json(userData);`);
    expect(rawErrorResponseRule.run(ctx)).toHaveLength(0);
  });
});

describe('ERR002 – Missing global error handler', () => {
  it('flags app.js without a 4-arg error handler', () => {
    const ctx = createContextFromFixture(
      `const express = require('express');\nconst app = express();\napp.use((req, res) => res.send('ok'));\napp.listen(3000);`,
      'app.js',
    );
    expect(missingErrorHandlerRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag when inline 4-arg handler is present', () => {
    const ctx = createContextFromFixture(
      `const app = express();\napp.use((err, req, res, next) => { res.status(500).json({ error: 'Internal' }); });\napp.listen(3000);`,
      'app.js',
    );
    expect(missingErrorHandlerRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag when a named function with "error" in the name is used', () => {
    // app.use(globalErrorHandler) — name contains "error"
    const ctx = createContextFromFixture(
      `const app = express();\napp.use(globalErrorHandler);\napp.listen(3000);`,
      'app.js',
    );
    expect(missingErrorHandlerRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag when named handler is defined in same file with 4 params', () => {
    const ctx = createContextFromFixture(
      `const app = express();
const handleErrors = (err, req, res, next) => { res.status(500).json({ error: 'oops' }); };
app.use(handleErrors);
app.listen(3000);`,
      'app.js',
    );
    expect(missingErrorHandlerRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag when named handler is defined in another project file with 4 params', () => {
    const { writeFileSync, unlinkSync } = require('fs');
    const { join } = require('path');
    const { tmpdir } = require('os');

    const handlerFile = join(tmpdir(), `ea-test-errhandler-${Date.now()}.ts`);
    writeFileSync(
      handlerFile,
      `export const myErrorMiddleware = (err: Error, req: any, res: any, next: any) => {\n  res.status(500).json({ error: 'Internal' });\n};`,
    );

    const ctx = createContextFromFixture(
      `const app = express();\napp.use(myErrorMiddleware);\napp.listen(3000);`,
      'app.js',
    );
    const ctxWithFiles = { ...ctx, allFiles: [ctx.filePath, handlerFile] };

    try {
      expect(missingErrorHandlerRule.run(ctxWithFiles)).toHaveLength(0);
    } finally {
      try { unlinkSync(handlerFile); } catch {}
    }
  });

  it('does not flag non-entry files', () => {
    const ctx = createContextFromFixture(`const x = 1;`, 'services/user.ts');
    expect(missingErrorHandlerRule.run(ctx)).toHaveLength(0);
  });
});
