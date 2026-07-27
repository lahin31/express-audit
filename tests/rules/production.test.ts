import { describe, it, expect } from 'vitest';
import {
  healthEndpointRule,
  gracefulShutdownRule,
  trustProxyRule,
  compressionMissingRule,
} from '../../src/rules/production/production-readiness.js';
import { createContextFromFixture } from '../helpers.js';

// All test sources include app.use() or app.listen() so isAppFile recognises
// them as entry files (the Express-presence check).
const APP_PREAMBLE = "const app = express(); app.use(express.json()); ";

const appCtx = (source: string) =>
  createContextFromFixture(APP_PREAMBLE + source, 'index.js');

describe('PROD001 – Missing health endpoint', () => {
  it('flags index.js without a /health route', () => {
    const ctx = appCtx(`app.listen(3000);`);
    expect(healthEndpointRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag when /health route exists', () => {
    const ctx = appCtx(`app.get('/health', (req, res) => res.json({ status: 'ok' })); app.listen(3000);`);
    expect(healthEndpointRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag when /ping route exists', () => {
    const ctx = appCtx(`app.get('/ping', (req, res) => res.send('pong')); app.listen(3000);`);
    expect(healthEndpointRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag a nested router file', () => {
    // src/router/index.ts — depth 2, should be skipped entirely
    const ctx = createContextFromFixture(
      `import { Router } from 'express'; const router = Router(); router.get('/users', handler);`,
      'src/router/index.ts',
    );
    expect(healthEndpointRule.run(ctx)).toHaveLength(0);
  });
});

describe('PROD002 – Missing graceful shutdown', () => {
  it('flags index.js without SIGTERM handler', () => {
    const ctx = appCtx(`app.listen(3000);`);
    expect(gracefulShutdownRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag when SIGTERM is handled', () => {
    const ctx = appCtx(`app.listen(3000); process.on('SIGTERM', () => server.close());`);
    expect(gracefulShutdownRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag when server.close() is present', () => {
    const ctx = appCtx(`app.listen(3000); server.close(() => process.exit(0));`);
    expect(gracefulShutdownRule.run(ctx)).toHaveLength(0);
  });
});

describe('PROD003 – Missing trust proxy', () => {
  it('flags index.js without trust proxy', () => {
    const ctx = appCtx(`app.listen(3000);`);
    expect(trustProxyRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag when trust proxy is set', () => {
    const ctx = appCtx(`app.set('trust proxy', 1); app.listen(3000);`);
    expect(trustProxyRule.run(ctx)).toHaveLength(0);
  });
});

describe('PROD004 – Compression missing', () => {
  it('flags app.js without compression', () => {
    const ctx = createContextFromFixture(
      `const express = require('express'); const app = express(); app.listen(3000);`,
      'app.js',
    );
    expect(compressionMissingRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag when compression is imported (ESM)', () => {
    const ctx = createContextFromFixture(
      `import compression from 'compression'; const app = express(); app.use(compression());`,
      'app.js',
    );
    expect(compressionMissingRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag when compression is required (CJS)', () => {
    const ctx = createContextFromFixture(
      `const compression = require('compression'); const app = express(); app.use(compression());`,
      'app.js',
    );
    expect(compressionMissingRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag a nested middleware file', () => {
    // src/router/index.ts — depth 2, should be skipped
    const ctx = createContextFromFixture(
      `import { Router } from 'express'; export const router = Router();`,
      'src/router/index.ts',
    );
    expect(compressionMissingRule.run(ctx)).toHaveLength(0);
  });
});
