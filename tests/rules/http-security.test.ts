import { describe, it, expect } from 'vitest';
import { helmetMissingRule } from '../../src/rules/http-security/helmet-missing.js';
import { cspMissingRule } from '../../src/rules/http-security/csp-missing.js';
import { xPoweredByRule } from '../../src/rules/http-security/xpoweredby.js';
import { createContextFromFixture } from '../helpers.js';

// ---------------------------------------------------------------------------
// HTTP001 – Helmet missing
// ---------------------------------------------------------------------------
describe('HTTP001 – Helmet missing', () => {
  it('flags app.js entry file without helmet', () => {
    const ctx = createContextFromFixture(
      `const express = require('express');\nconst app = express();\napp.listen(3000);`,
      'app.js',
    );
    expect(helmetMissingRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag when helmet is imported', () => {
    const ctx = createContextFromFixture(
      `import helmet from 'helmet';\napp.use(helmet());`,
      'app.js',
    );
    expect(helmetMissingRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag non-entry files', () => {
    const ctx = createContextFromFixture(
      `const x = 1;`,
      'routes/users.ts',
    );
    expect(helmetMissingRule.run(ctx)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// CSP001 – Missing CSP
// ---------------------------------------------------------------------------
describe('CSP001 – Missing Content Security Policy', () => {
  it('flags app.js without CSP configuration', () => {
    const ctx = createContextFromFixture(
      `const express = require('express');\napp.listen(3000);`,
      'app.js',
    );
    expect(cspMissingRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag when helmet() is used (CSP enabled by default)', () => {
    const ctx = createContextFromFixture(
      `import helmet from 'helmet';\napp.use(helmet());`,
      'app.js',
    );
    expect(cspMissingRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag when helmet.contentSecurityPolicy() is used explicitly', () => {
    const ctx = createContextFromFixture(
      `const app = express();\napp.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["'self'"] } }));`,
      'app.js',
    );
    expect(cspMissingRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag non-entry files', () => {
    const ctx = createContextFromFixture(`const x = 1;`, 'utils/helper.ts');
    expect(cspMissingRule.run(ctx)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// HEADER001 – X-Powered-By enabled
// ---------------------------------------------------------------------------
describe('HEADER001 – X-Powered-By', () => {
  it('flags server.js without x-powered-by disabled', () => {
    const ctx = createContextFromFixture(
      `const express = require('express');\nconst app = express();`,
      'server.js',
    );
    expect(xPoweredByRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag when app.disable("x-powered-by") is present', () => {
    const ctx = createContextFromFixture(
      `const app = express();\napp.disable('x-powered-by');\napp.listen(3000);`,
      'server.js',
    );
    expect(xPoweredByRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag when helmet is used', () => {
    const ctx = createContextFromFixture(
      `import helmet from 'helmet';\nconst app = express();\napp.use(helmet());`,
      'server.js',
    );
    expect(xPoweredByRule.run(ctx)).toHaveLength(0);
  });
});
