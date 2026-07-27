import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { findImports } from '../../core/ast-helpers.js';

export const rateLimitMissingRule: Rule = {
  id: 'RATE001',
  severity: 'medium',
  category: 'Rate Limiting',
  title: 'No Rate Limiting Detected',
  description: 'No rate limiting middleware detected in the application',
  detectorType: 'ast',
  remediation: 'Install and use express-rate-limit: npm install express-rate-limit && app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }))',
  references: [
    {
      title: 'express-rate-limit Documentation',
      url: 'https://www.npmjs.com/package/express-rate-limit',
    },
    {
      title: 'OWASP - API Security Top 10: Unrestricted Resource Consumption',
      url: 'https://owasp.org/www-project-api-security/',
    },
    {
      title: 'Express Security Best Practices',
      url: 'https://expressjs.com/en/advanced/best-practice-security.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const isAppFile =
      context.filePath.endsWith('app.ts') ||
      context.filePath.endsWith('app.js') ||
      context.filePath.endsWith('server.ts') ||
      context.filePath.endsWith('server.js') ||
      context.filePath.endsWith('index.ts') ||
      context.filePath.endsWith('index.js');

    if (!isAppFile) return [];

    const ast = context.ast as File;

    const hasRateLimit =
      findImports(ast, 'express-rate-limit') ||
      findImports(ast, 'rate-limiter-flexible') ||
      findImports(ast, 'express-slow-down') ||
      findImports(ast, 'bottleneck') ||
      findImports(ast, '@nestjs/throttler') ||
      findImports(ast, 'express-brute');

    if (!hasRateLimit) {
      return [{
        ruleId: 'RATE001',
        severity: 'medium',
        category: 'Rate Limiting',
        title: 'No Rate Limiting Detected',
        description: 'No rate limiting middleware found in application entry point',
        impact: 'Without rate limiting, the application is vulnerable to brute-force attacks, denial-of-service, and credential stuffing.',
        remediation: `Install express-rate-limit and add:
const rateLimit = require('express-rate-limit');
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));`,
        references: rateLimitMissingRule.references,
        filePath: context.filePath,
      }];
    }

    return [];
  },
};
