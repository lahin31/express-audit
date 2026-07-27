import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { findImports } from '../../core/ast-helpers.js';
import { isEntryFile } from '../../core/is-entry-file.js';
import { bothStyles } from '../../core/remediation.js';

export const helmetMissingRule: Rule = {
  id: 'HTTP001',
  severity: 'high',
  category: 'HTTP Security',
  title: 'Helmet Middleware Missing',
  description: 'The helmet security middleware is not used, leaving the application vulnerable to common HTTP attacks',
  detectorType: 'ast',
  remediation: bothStyles('helmet', 'helmet', 'app.use(helmet());'),
  references: [
    {
      title: 'Helmet.js Documentation',
      url: 'https://helmetjs.github.io/',
    },
    {
      title: 'OWASP - Secure Headers Project',
      url: 'https://owasp.org/www-project-secure-headers/',
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
    const hasHelmet = findImports(ast, 'helmet');

    if (hasHelmet) return [];

    return [{
      ruleId: 'HTTP001',
      severity: 'high',
      category: 'HTTP Security',
      title: 'Helmet Middleware Missing',
      description: 'No helmet middleware detected in application entry point',
      impact: 'Without helmet, Express sets no security headers, leaving the app vulnerable to XSS, clickjacking, MIME-sniffing, and other attacks.',
      remediation: helmetMissingRule.remediation,
      references: helmetMissingRule.references,
      filePath: context.filePath,
    }];
  },
};
