import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { findImports } from '../../core/ast-helpers.js';

export const helmetMissingRule: Rule = {
  id: 'HTTP001',
  severity: 'high',
  category: 'HTTP Security',
  title: 'Helmet Middleware Missing',
  description: 'The helmet security middleware is not used, leaving the application vulnerable to common HTTP attacks',
  detectorType: 'ast',
  remediation: 'Install and use helmet: npm install helmet && app.use(helmet())',
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

    const ast = context.ast as File;
    const hasHelmet = findImports(ast, 'helmet');

    if (!hasHelmet) {
      // Only report once per project - check if it's likely a main app file
      const isAppFile = 
        context.filePath.endsWith('app.ts') ||
        context.filePath.endsWith('app.js') ||
        context.filePath.endsWith('server.ts') ||
        context.filePath.endsWith('server.js') ||
        context.filePath.endsWith('index.ts') ||
        context.filePath.endsWith('index.js') ||
        context.filePath.endsWith('main.ts') ||
        context.filePath.endsWith('main.js');

      if (!isAppFile) return [];

      return [{
        ruleId: 'HTTP001',
        severity: 'high',
        category: 'HTTP Security',
        title: 'Helmet Middleware Missing',
        description: 'No helmet middleware detected in application entry point',
        impact: 'Without helmet, Express sets no security headers, leaving the app vulnerable to XSS, clickjacking, MIME-sniffing, and other attacks.',
        remediation: 'Add: const helmet = require("helmet"); app.use(helmet());',
        references: helmetMissingRule.references,
        filePath: context.filePath,
      }];
    }

    return [];
  },
};
