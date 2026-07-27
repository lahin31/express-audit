import { describe, it, expect } from 'vitest';
import {
  healthEndpointRule,
  gracefulShutdownRule,
  trustProxyRule,
  compressionMissingRule,
} from '../../src/rules/production/production-readiness.js';
import { createContextFromFixture } from '../helpers.js';

const appCtx = (source: string) => createContextFromFixture(source, 'index.js');

describe('PROD001 – Missing health endpoint', () => {
  it('flags index.js without a /health route', () => {
    const ctx = appCtx(`const express = require('express');\napp.listen(3000);`);
    expect(healthEndpointRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag when /health route exists', () => {
    const ctx = appCtx(`app.get('/health', (req, res) => res.json({ status: 'ok' }));`);
    expect(healthEndpointRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag when /ping route exists', () => {
    const ctx = appCtx(`app.get('/ping', (req, res) => res.send('pong'));`);
    expect(healthEndpointRule.run(ctx)).toHaveLength(0);
  });
});

describe('PROD002 – Missing graceful shutdown', () => {
  it('flags index.js without SIGTERM handler', () => {
    const ctx = appCtx(`const app = express();\napp.listen(3000);`);
    expect(gracefulShutdownRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag when SIGTERM is handled', () => {
    const ctx = appCtx(`process.on('SIGTERM', () => server.close());`);
    expect(gracefulShutdownRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag when server.close() is present', () => {
    const ctx = appCtx(`server.close(() => process.exit(0));`);
    expect(gracefulShutdownRule.run(ctx)).toHaveLength(0);
  });
});

describe('PROD003 – Missing trust proxy', () => {
  it('flags index.js without trust proxy', () => {
    const ctx = appCtx(`const app = express();\napp.listen(3000);`);
    expect(trustProxyRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag when trust proxy is set', () => {
    const ctx = appCtx(`app.set('trust proxy', 1);`);
    expect(trustProxyRule.run(ctx)).toHaveLength(0);
  });
});

describe('PROD004 – Compression missing', () => {
  it('flags app.js without compression', () => {
    const ctx = createContextFromFixture(`const express = require('express');\napp.listen(3000);`, 'app.js');
    expect(compressionMissingRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag when compression is imported', () => {
    const ctx = createContextFromFixture(
      `import compression from 'compression';\napp.use(compression());`,
      'app.js',
    );
    expect(compressionMissingRule.run(ctx)).toHaveLength(0);
  });
});
