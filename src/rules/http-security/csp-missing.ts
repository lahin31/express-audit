import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getObjectProperty } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';
import { isEntryFile } from '../../core/is-entry-file.js';
import { parseFile } from '../../parser/index.js';
import { readFileSync, existsSync } from 'fs';

/**
 * Returns true if the given AST contains a CSP configuration.
 */
function astHasCSP(ast: File): boolean {
  let found = false;

  traverse(ast, {
    CallExpression(path: NodePath<BabelTypes.CallExpression>) {
      const callee = path.node.callee;

      // helmet.contentSecurityPolicy()
      if (
        callee.type === 'MemberExpression' &&
        callee.property.type === 'Identifier' &&
        callee.property.name === 'contentSecurityPolicy'
      ) {
        found = true;
      }

      // helmet() with no args — includes CSP by default
      // helmet({ contentSecurityPolicy: ... }) — only if not explicitly false
      if (callee.type === 'Identifier' && callee.name === 'helmet') {
        const arg = path.node.arguments[0];
        if (!arg) {
          found = true;
        } else if (arg.type === 'ObjectExpression') {
          const cspProp = getObjectProperty(arg, 'contentSecurityPolicy');
          if (cspProp) {
            if (
              cspProp.type !== 'BooleanLiteral' ||
              (cspProp as BabelTypes.BooleanLiteral).value !== false
            ) {
              found = true;
            }
          }
        }
      }

      // res.setHeader('Content-Security-Policy', ...)
      if (
        callee.type === 'MemberExpression' &&
        callee.property.type === 'Identifier' &&
        callee.property.name === 'setHeader'
      ) {
        const keyArg = path.node.arguments[0];
        if (
          keyArg?.type === 'StringLiteral' &&
          keyArg.value.toLowerCase().includes('content-security-policy')
        ) {
          found = true;
        }
      }
    },
  });

  return found;
}

export const cspMissingRule: Rule = {
  id: 'CSP001',
  severity: 'medium',
  category: 'HTTP Security',
  title: 'Missing Content Security Policy',
  description: 'No Content Security Policy (CSP) header is configured',
  detectorType: 'ast',
  remediation: "Configure CSP with helmet: app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self'\"] } }))",
  references: [
    {
      title: 'MDN – Content Security Policy',
      url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
    },
    {
      title: 'OWASP CSP Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
    },
    {
      title: 'OWASP ASVS v4.0 – V14.4.6: Content Security Policy',
      url: 'https://owasp.org/www-project-application-security-verification-standard/',
    },
    {
      title: 'OWASP Top 10 2021 – A03: Injection (XSS)',
      url: 'https://owasp.org/Top10/A03_2021-Injection/',
    },
    {
      title: 'W3C – Content Security Policy Level 3',
      url: 'https://www.w3.org/TR/CSP3/',
    },
    {
      title: 'Google CSP Guide',
      url: 'https://developers.google.com/web/fundamentals/security/csp',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];
    if (!isEntryFile(context.filePath, context.projectRoot, context.source)) return [];

    // Check the entry file first
    if (astHasCSP(context.ast as File)) return [];

    // Scan all project files — CSP may be set in a dedicated middleware file
    for (const filePath of context.allFiles) {
      if (filePath === context.filePath) continue;
      if (!existsSync(filePath)) continue;

      let src: string;
      try { src = readFileSync(filePath, 'utf-8'); } catch { continue; }
      // Quick string filter before full parse
      if (!src.includes('helmet') && !src.includes('content-security-policy')) continue;

      const { ast } = parseFile(filePath);
      if (ast && astHasCSP(ast)) return [];
    }

    return [{
      ruleId: 'CSP001',
      severity: 'medium',
      category: 'HTTP Security',
      title: 'Missing Content Security Policy',
      description: 'No Content Security Policy header detected in the project',
      impact: 'Without CSP, the application is vulnerable to Cross-Site Scripting (XSS) and data injection attacks.',
      remediation: cspMissingRule.remediation,
      references: cspMissingRule.references,
      filePath: context.filePath,
    }];
  },
};
