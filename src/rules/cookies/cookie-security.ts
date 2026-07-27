import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getObjectProperty, isBoolFalse, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

/**
 * Checks cookie configuration for security best practices.
 * Covers: res.cookie(), cookieParser options, express-session cookie options
 */
export const cookieSecurityRule: Rule = {
  id: 'COOKIE001',
  severity: 'high',
  category: 'Cookies',
  title: 'Insecure Cookie Configuration',
  description: 'Cookies are missing security flags: httpOnly, secure, or sameSite',
  detectorType: 'ast',
  remediation: 'Set secure cookie options: res.cookie("name", value, { httpOnly: true, secure: true, sameSite: "strict" })',
  references: [
    {
      title: 'OWASP - Secure Cookie Attribute',
      url: 'https://owasp.org/www-community/controls/SecureCookieAttribute',
    },
    {
      title: 'MDN - Set-Cookie',
      url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie',
    },
    {
      title: 'Express Cookie Documentation',
      url: 'https://expressjs.com/en/api.html#res.cookie',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        // Check for res.cookie(name, value, options)
        const isCookieCall =
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          callee.property.name === 'cookie' &&
          callee.object.type === 'Identifier';

        if (isCookieCall) {
          const optionsArg = path.node.arguments[2];
          const line = getNodeLine(path.node);

          if (!optionsArg) {
            findings.push({
              ruleId: 'COOKIE001',
              severity: 'high',
              category: 'Cookies',
              title: 'Cookie Missing Security Options',
              description: 'res.cookie() called without security options',
              impact: 'Cookies without httpOnly can be accessed by JavaScript (XSS theft). Without secure, cookies are sent over HTTP.',
              remediation: 'Add options: res.cookie(name, value, { httpOnly: true, secure: true, sameSite: "strict" })',
              references: cookieSecurityRule.references,
              filePath: context.filePath,
              line,
            });
            return;
          }

          if (optionsArg.type === 'ObjectExpression') {
            const httpOnly = getObjectProperty(optionsArg, 'httpOnly');
            const secure = getObjectProperty(optionsArg, 'secure');
            const sameSite = getObjectProperty(optionsArg, 'sameSite');

            if (!httpOnly || isBoolFalse(httpOnly)) {
              findings.push({
                ruleId: 'COOKIE001',
                severity: 'high',
                category: 'Cookies',
                title: 'Cookie Missing httpOnly Flag',
                description: 'Cookie is not set with httpOnly: true',
                impact: 'Cookies accessible via JavaScript can be stolen through XSS attacks.',
                remediation: 'Add httpOnly: true to cookie options',
                references: cookieSecurityRule.references,
                filePath: context.filePath,
                line,
              });
            }

            if (!secure || isBoolFalse(secure)) {
              findings.push({
                ruleId: 'COOKIE001',
                severity: 'high',
                category: 'Cookies',
                title: 'Cookie Missing Secure Flag',
                description: 'Cookie is not set with secure: true',
                impact: 'Cookies without the Secure flag can be transmitted over insecure HTTP connections.',
                remediation: 'Add secure: true to cookie options (use process.env.NODE_ENV === "production" check if needed)',
                references: cookieSecurityRule.references,
                filePath: context.filePath,
                line,
              });
            }

            if (!sameSite) {
              findings.push({
                ruleId: 'COOKIE001',
                severity: 'medium',
                category: 'Cookies',
                title: 'Cookie Missing SameSite Attribute',
                description: 'Cookie does not have sameSite attribute set',
                impact: 'Cookies without SameSite are vulnerable to Cross-Site Request Forgery (CSRF) attacks.',
                remediation: 'Add sameSite: "strict" or sameSite: "lax" to cookie options',
                references: cookieSecurityRule.references,
                filePath: context.filePath,
                line,
              });
            }
          }
        }
      },
    });

    return findings;
  },
};
