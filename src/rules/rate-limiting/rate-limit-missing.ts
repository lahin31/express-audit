import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { findImports } from '../../core/ast-helpers.js';
import { isEntryFile } from '../../core/is-entry-file.js';
import { bothStyles } from '../../core/remediation.js';
import { parseFile } from '../../parser/index.js';
import { readFileSync, existsSync } from 'fs';

export const rateLimitMissingRule: Rule = {
  id: 'RATE001',
  severity: 'medium',
  category: 'Rate Limiting',
  title: 'No Rate Limiting Detected',
  description: 'No rate limiting middleware detected in the project',
  detectorType: 'ast',
  remediation: bothStyles('express-rate-limit', 'rateLimit', 'app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));', true),
  references: [
    {
      title: 'OWASP API Security Top 10 2023 – API4: Unrestricted Resource Consumption',
      url: 'https://owasp.org/www-project-api-security/',
    },
    {
      title: 'OWASP ASVS v4.0 – V13.2.6: Rate Limiting',
      url: 'https://owasp.org/www-project-application-security-verification-standard/',
    },
    {
      title: 'OWASP Denial of Service Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html',
    },
    {
      title: 'CWE-770: Allocation of Resources Without Limits or Throttling',
      url: 'https://cwe.mitre.org/data/definitions/770.html',
    },
    {
      title: 'Express Security Best Practices',
      url: 'https://expressjs.com/en/advanced/best-practice-security.html',
    },
    {
      title: 'express-rate-limit Documentation',
      url: 'https://www.npmjs.com/package/express-rate-limit',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];
    if (!isEntryFile(context.filePath, context.projectRoot, context.source)) return [];

    const RATE_LIMIT_PACKAGES = [
      'express-rate-limit',
      'rate-limiter-flexible',
      'express-slow-down',
      'bottleneck',
      '@nestjs/throttler',
      'express-brute',
    ];

    // Check the entry file itself first
    const entryAst = context.ast as File;
    if (RATE_LIMIT_PACKAGES.some(pkg => findImports(entryAst, pkg))) return [];

    // Scan all project files — rate limiting may be configured in a
    // dedicated middleware file imported into the entry file
    for (const filePath of context.allFiles) {
      if (filePath === context.filePath) continue;
      if (!existsSync(filePath)) continue;

      // Fast string filter before parsing
      let src: string;
      try { src = readFileSync(filePath, 'utf-8'); } catch { continue; }
      const mentionsRateLimit = RATE_LIMIT_PACKAGES.some(pkg => src.includes(pkg.split('/').pop()!));
      if (!mentionsRateLimit) continue;

      const { ast } = parseFile(filePath);
      if (ast && RATE_LIMIT_PACKAGES.some(pkg => findImports(ast, pkg))) return [];
    }

    return [{
      ruleId: 'RATE001',
      severity: 'medium',
      category: 'Rate Limiting',
      title: 'No Rate Limiting Detected',
      description: 'No rate limiting middleware found in the project',
      impact: 'Without rate limiting, the application is vulnerable to brute-force attacks, denial-of-service, and credential stuffing.',
      remediation: rateLimitMissingRule.remediation,
      references: rateLimitMissingRule.references,
      filePath: context.filePath,
    }];
  },
};
