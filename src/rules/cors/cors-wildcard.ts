import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getObjectProperty, getStringValue, isBoolTrue, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

export const corsWildcardRule: Rule = {
  id: 'CORS001',
  severity: 'high',
  category: 'CORS',
  title: 'CORS Wildcard Origin',
  description: 'CORS is configured to allow all origins (*), which is dangerous especially with credentials',
  detectorType: 'ast',
  remediation: 'Specify exact allowed origins: cors({ origin: ["https://yourdomain.com"] })',
  references: [
    {
      title: 'OWASP CORS Origin Header Scrutiny',
      url: 'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny',
    },
    {
      title: 'OWASP ASVS v4.0 – V14.4: HTTP Security Headers',
      url: 'https://owasp.org/www-project-application-security-verification-standard/',
    },
    {
      title: 'OWASP Top 10 2021 – A05: Security Misconfiguration',
      url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    },
    {
      title: 'W3C – Cross-Origin Resource Sharing Specification',
      url: 'https://www.w3.org/TR/cors/',
    },
    {
      title: 'MDN – Cross-Origin Resource Sharing (CORS)',
      url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
    },
    {
      title: 'Express CORS Middleware',
      url: 'https://expressjs.com/en/resources/middleware/cors.html',
    },
    {
      title: 'CWE-942: Permissive Cross-domain Policy',
      url: 'https://cwe.mitre.org/data/definitions/942.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        // Detect cors() calls — may appear standalone or nested inside app.use(cors())
        const isCors =
          callee.type === 'Identifier' && callee.name === 'cors';

        if (!isCors) return;

        const optionsArg = path.node.arguments[0];
        const line = getNodeLine(path.node);

        // cors() with no options = wildcard
        if (!optionsArg) {
          findings.push({
            ruleId: 'CORS001',
            severity: 'high',
            category: 'CORS',
            title: 'CORS Allows All Origins',
            description: 'cors() called without options allows all origins (*)',
            impact: 'Any website can make cross-origin requests to your API.',
            remediation: 'Specify allowed origins: cors({ origin: ["https://yourdomain.com"] })',
            references: corsWildcardRule.references,
            filePath: context.filePath,
            line,
          });
          return;
        }

        if (optionsArg.type === 'ObjectExpression') {
          const origin = getObjectProperty(optionsArg, 'origin');
          const credentials = getObjectProperty(optionsArg, 'credentials');

          if (!origin) {
            findings.push({
              ruleId: 'CORS001',
              severity: 'high',
              category: 'CORS',
              title: 'CORS Missing Origin Restriction',
              description: 'cors() options do not specify origin restriction',
              impact: 'Without origin restriction, all origins are allowed.',
              remediation: 'Add: origin: ["https://yourdomain.com"]',
              references: corsWildcardRule.references,
              filePath: context.filePath,
              line,
            });
            return;
          }

          const originValue = getStringValue(origin);

          // Check for explicit wildcard
          if (originValue === '*') {
            const hasCredentials = isBoolTrue(credentials);

            if (hasCredentials) {
              // This is actually rejected by browsers but shows intent mismatch
              findings.push({
                ruleId: 'CORS001',
                severity: 'critical',
                category: 'CORS',
                title: 'CORS Wildcard with Credentials',
                description: 'CORS configured with origin: "*" and credentials: true',
                impact: 'Browsers reject this combination, but the intent reveals misconfigured CORS. This could be a security misconfiguration.',
                remediation: 'Specify exact origins when using credentials: cors({ origin: "https://yourdomain.com", credentials: true })',
                references: corsWildcardRule.references,
                filePath: context.filePath,
                line,
              });
            } else {
              findings.push({
                ruleId: 'CORS001',
                severity: 'high',
                category: 'CORS',
                title: 'CORS Wildcard Origin',
                description: 'CORS is configured with origin: "*"',
                impact: 'Any website can make cross-origin requests to your API.',
                remediation: 'Specify exact allowed origins: cors({ origin: ["https://yourdomain.com"] })',
                references: corsWildcardRule.references,
                filePath: context.filePath,
                line,
              });
            }
          }

          // Check for dynamic origin validation (function) - potential for bypass
          if (origin.type === 'ArrowFunctionExpression' || origin.type === 'FunctionExpression') {
            findings.push({
              ruleId: 'CORS001',
              severity: 'medium',
              category: 'CORS',
              title: 'Dynamic CORS Origin Validation',
              description: 'CORS origin is validated with a function. Ensure the validation logic is strict.',
              impact: 'Weak origin validation can allow unauthorized origins. Ensure no regex bypass vulnerabilities exist.',
              remediation: 'Use an explicit allowlist: const allowedOrigins = ["https://yourdomain.com"]; ensure strict matching.',
              references: corsWildcardRule.references,
              filePath: context.filePath,
              line,
            });
          }
        }
      },
    });

    return findings;
  },
};
