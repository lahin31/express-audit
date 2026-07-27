import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { findImports } from '../../core/ast-helpers.js';
import { isEntryFile } from '../../core/is-entry-file.js';
import { bothStyles } from '../../core/remediation.js';
import { parseFile } from '../../parser/index.js';
import { readFileSync, existsSync } from 'fs';

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

    // 1. Check the entry file itself
    const entryAst = context.ast as File;
    if (findImports(entryAst, 'helmet')) return [];

    // 2. Scan ALL project files — helmet may be imported in a dedicated
    //    middleware setup file (e.g. middlewares/common/default.middleware.ts)
    //    and never appear in index.ts directly.
    for (const filePath of context.allFiles) {
      if (filePath === context.filePath) continue; // already checked above
      if (!existsSync(filePath)) continue;

      // Fast string check before parsing — avoids AST overhead for files
      // that clearly don't reference helmet
      let src: string;
      try { src = readFileSync(filePath, 'utf-8'); } catch { continue; }
      if (!src.includes('helmet')) continue;

      // Full AST check to confirm it's an actual import/require, not a comment
      const { ast } = parseFile(filePath);
      if (ast && findImports(ast, 'helmet')) return [];
    }

    return [{
      ruleId: 'HTTP001',
      severity: 'high',
      category: 'HTTP Security',
      title: 'Helmet Middleware Missing',
      description: 'No helmet middleware detected in the project',
      impact: 'Without helmet, Express sets no security headers, leaving the app vulnerable to XSS, clickjacking, MIME-sniffing, and other attacks.',
      remediation: helmetMissingRule.remediation,
      references: helmetMissingRule.references,
      filePath: context.filePath,
    }];
  },
};
