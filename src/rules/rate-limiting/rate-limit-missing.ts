import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { findImports } from '../../core/ast-helpers.js';
import { isEntryFile } from '../../core/is-entry-file.js';
import { bothStyles } from '../../core/remediation.js';

export const rateLimitMissingRule: Rule = {
  id: 'RATE001',
  severity: 'medium',
  category: 'Rate Limiting',
  title: 'No Rate Limiting Detected',
  description: 'No rate limiting middleware detected in the application',
  detectorType: 'ast',
  remediation: bothStyles('express-rate-limit', 'rateLimit', 'app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));', true),
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
    if (!isEntryFile(context.filePath, context.projectRoot, context.source)) return [];

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
        remediation: rateLimitMissingRule.remediation,
        references: rateLimitMissingRule.references,
        filePath: context.filePath,
      }];
    }

    return [];
  },
};
