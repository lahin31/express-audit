import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

const SENSITIVE_PROPERTY_NAMES = [
  'password', 'passwd', 'pass', 'pwd',
  'secret', 'token', 'apikey', 'api_key',
  'authorization', 'auth',
  'credential', 'credentials',
  'privatekey', 'private_key',
  'accesstoken', 'access_token', 'refreshtoken', 'refresh_token',
  'sessionid', 'session_id',
  'ssn', 'creditcard', 'credit_card', 'cvv', 'pin',
];

export const sensitiveLoggingRule: Rule = {
  id: 'LOG001',
  severity: 'high',
  category: 'Logging',
  title: 'Sensitive Data in Logs',
  description: 'Sensitive data (passwords, tokens, API keys) may be written to logs',
  detectorType: 'ast',
  remediation: 'Sanitize log output to remove sensitive fields. Use a log sanitizer or explicitly omit sensitive properties.',
  references: [
    {
      title: 'OWASP Top 10 2021 – A02: Cryptographic Failures (Sensitive Data Exposure)',
      url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    },
    {
      title: 'OWASP Logging Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
    },
    {
      title: 'OWASP ASVS v4.0 – V7.1: Log Content Requirements',
      url: 'https://owasp.org/www-project-application-security-verification-standard/',
    },
    {
      title: 'CWE-532: Information Exposure Through Log Files',
      url: 'https://cwe.mitre.org/data/definitions/532.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    const isLoggingCall = (node: BabelTypes.CallExpression): boolean => {
      const callee = node.callee;
      // console.log, console.error, console.warn, console.info, console.debug
      if (
        callee.type === 'MemberExpression' &&
        callee.object.type === 'Identifier' &&
        callee.object.name === 'console' &&
        callee.property.type === 'Identifier'
      ) {
        return ['log', 'error', 'warn', 'info', 'debug', 'trace'].includes(
          callee.property.name
        );
      }
      // winston.info, logger.info, logger.error, etc.
      if (
        callee.type === 'MemberExpression' &&
        callee.object.type === 'Identifier' &&
        ['logger', 'log', 'winston', 'pino', 'bunyan'].includes(callee.object.name) &&
        callee.property.type === 'Identifier'
      ) {
        return ['info', 'error', 'warn', 'debug', 'verbose', 'log'].includes(
          callee.property.name
        );
      }
      return false;
    };

    const isSensitiveMemberAccess = (node: BabelTypes.Node): boolean => {
      if (node.type !== 'MemberExpression') return false;
      const prop = (node as BabelTypes.MemberExpression).property;
      if (prop.type === 'Identifier') {
        return SENSITIVE_PROPERTY_NAMES.includes(prop.name.toLowerCase());
      }
      if (prop.type === 'StringLiteral') {
        return SENSITIVE_PROPERTY_NAMES.includes(prop.value.toLowerCase());
      }
      return false;
    };

    const checkArgForSensitiveData = (arg: BabelTypes.Node): string | null => {
      if (isSensitiveMemberAccess(arg)) {
        const prop = (arg as BabelTypes.MemberExpression).property;
        const propName = prop.type === 'Identifier' ? prop.name : (prop as BabelTypes.StringLiteral).value;
        return propName;
      }
      return null;
    };

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        if (!isLoggingCall(path.node)) return;

        for (const arg of path.node.arguments) {
          // Direct sensitive property access: console.log(user.password)
          const sensitiveProp = checkArgForSensitiveData(arg);
          if (sensitiveProp) {
            findings.push({
              ruleId: 'LOG001',
              severity: 'high',
              category: 'Logging',
              title: 'Sensitive Data in Logs',
              description: `Potentially sensitive property "${sensitiveProp}" is being logged`,
              impact: 'Sensitive credentials written to logs can be exposed through log aggregation systems, storage, or unauthorized access.',
              remediation: `Remove ${sensitiveProp} from log output or use a sanitizer function`,
              references: sensitiveLoggingRule.references,
              filePath: context.filePath,
              line: getNodeLine(path.node),
            });
          }

          // Check objects being spread/logged: console.log(req.body)
          if (
            arg.type === 'MemberExpression' &&
            arg.object.type === 'Identifier' &&
            arg.object.name === 'req' &&
            arg.property.type === 'Identifier' &&
            arg.property.name === 'body'
          ) {
            findings.push({
              ruleId: 'LOG002',
              severity: 'medium',
              category: 'Logging',
              title: 'Logging Request Body',
              description: 'Entire request body is being logged, which may contain sensitive data',
              impact: 'Request bodies often contain passwords, tokens, and personal data.',
              remediation: 'Log only specific safe fields, not the entire request body',
              references: sensitiveLoggingRule.references,
              filePath: context.filePath,
              line: getNodeLine(path.node),
            });
          }
        }
      },
    });

    return findings;
  },
};

/**
 * Detect when error stack traces are sent to clients
 */
export const stackTraceExposureRule: Rule = {
  id: 'LOG003',
  severity: 'medium',
  category: 'Logging',
  title: 'Stack Trace Exposed to Client',
  description: 'Error stack traces are returned in HTTP responses',
  detectorType: 'ast',
  remediation: 'Never return stack traces to clients in production. Log errors server-side and return generic error messages.',
  references: [
    {
      title: 'OWASP – Improper Error Handling',
      url: 'https://owasp.org/www-community/Improper_Error_Handling',
    },
    {
      title: 'OWASP ASVS v4.0 – V7.4: Error Handling',
      url: 'https://owasp.org/www-project-application-security-verification-standard/',
    },
    {
      title: 'OWASP Top 10 2021 – A05: Security Misconfiguration',
      url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    },
    {
      title: 'CWE-209: Generation of Error Message Containing Sensitive Information',
      url: 'https://cwe.mitre.org/data/definitions/209.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        // Look for res.json() or res.send()
        const isResponseCall =
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          (callee.property.name === 'json' || 
           callee.property.name === 'send' || 
           callee.property.name === 'status') &&
          callee.object.type === 'Identifier';

        if (!isResponseCall) return;

        // Check arguments for error.stack or err.stack
        const checkForStack = (node: BabelTypes.Node): boolean => {
          if (
            node.type === 'MemberExpression' &&
            node.property.type === 'Identifier' &&
            node.property.name === 'stack' &&
            node.object.type === 'Identifier' &&
            ['err', 'error', 'e', 'ex', 'exception'].includes(
              (node.object as BabelTypes.Identifier).name
            )
          ) {
            return true;
          }
          if (node.type === 'ObjectExpression') {
            for (const prop of (node as BabelTypes.ObjectExpression).properties) {
              if (prop.type === 'ObjectProperty' && checkForStack(prop.value)) {
                return true;
              }
            }
          }
          return false;
        };

        for (const arg of path.node.arguments) {
          if (checkForStack(arg)) {
            findings.push({
              ruleId: 'LOG003',
              severity: 'medium',
              category: 'Logging',
              title: 'Stack Trace Exposed to Client',
              description: 'Error stack trace is included in HTTP response',
              impact: 'Stack traces reveal internal code structure, file paths, and dependencies, aiding attackers in targeted exploits.',
              remediation: 'Log errors server-side and return a generic error message to clients',
              references: stackTraceExposureRule.references,
              filePath: context.filePath,
              line: getNodeLine(path.node),
            });
          }
        }
      },
    });

    return findings;
  },
};
