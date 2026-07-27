import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getObjectProperty, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

export const cspMissingRule: Rule = {
  id: 'CSP001',
  severity: 'medium',
  category: 'HTTP Security',
  title: 'Missing Content Security Policy',
  description: 'No Content Security Policy (CSP) header is configured',
  detectorType: 'ast',
  remediation: 'Configure CSP with helmet: app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["\'self\'"] } }))',
  references: [
    {
      title: 'MDN - Content Security Policy',
      url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
    },
    {
      title: 'OWASP CSP Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
    },
    {
      title: 'Google CSP Guide',
      url: 'https://developers.google.com/web/fundamentals/security/csp',
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
    let hasCSP = false;
    let hasHelmetWithoutCSP = false;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        // Check for helmet.contentSecurityPolicy()
        if (
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          callee.property.name === 'contentSecurityPolicy'
        ) {
          hasCSP = true;
        }

        // Check for helmet({ contentSecurityPolicy: ... })
        if (
          callee.type === 'Identifier' &&
          callee.name === 'helmet'
        ) {
          const arg = path.node.arguments[0];
          if (arg?.type === 'ObjectExpression') {
            const cspProp = getObjectProperty(arg, 'contentSecurityPolicy');
            if (cspProp) {
              // Check it's not explicitly disabled
              if (
                cspProp.type !== 'BooleanLiteral' ||
                (cspProp as BabelTypes.BooleanLiteral).value !== false
              ) {
                hasCSP = true;
              }
            }
          } else if (!arg) {
            // helmet() without options - it includes CSP by default
            hasCSP = true;
          }
        }

        // Check for res.setHeader('Content-Security-Policy', ...)
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
            hasCSP = true;
          }
        }
      },
    });

    if (!hasCSP) {
      return [{
        ruleId: 'CSP001',
        severity: 'medium',
        category: 'HTTP Security',
        title: 'Missing Content Security Policy',
        description: 'No Content Security Policy header detected',
        impact: 'Without CSP, the application is vulnerable to Cross-Site Scripting (XSS) and data injection attacks.',
        remediation: 'Use helmet with CSP: app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["\'self\'"] } } }))',
        references: cspMissingRule.references,
        filePath: context.filePath,
      }];
    }

    return [];
  },
};
