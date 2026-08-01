import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getObjectProperty, isBoolFalse, isBoolTrue, getStringValue, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

export const sessionSecurityRule: Rule = {
  id: 'SESSION001',
  severity: 'high',
  category: 'Sessions',
  title: 'Insecure Session Configuration',
  description: 'express-session is configured with insecure settings',
  detectorType: 'ast',
  remediation: 'Configure sessions securely with proper secret, saveUninitialized: false, resave: false, and cookie security options.',
  references: [
    {
      title: 'OWASP Session Management Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
    },
    {
      title: 'OWASP ASVS v4.0 – V3.2: Session Binding',
      url: 'https://owasp.org/www-project-application-security-verification-standard/',
    },
    {
      title: 'OWASP Top 10 2021 – A07: Identification and Authentication Failures',
      url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
    },
    {
      title: 'express-session Documentation',
      url: 'https://www.npmjs.com/package/express-session',
    },
    {
      title: 'CWE-384: Session Fixation',
      url: 'https://cwe.mitre.org/data/definitions/384.html',
    },
    {
      title: 'CWE-798: Use of Hard-coded Credentials',
      url: 'https://cwe.mitre.org/data/definitions/798.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        // Detect session() or expressSession() calls
        const isSession =
          (callee.type === 'Identifier' && (callee.name === 'session' || callee.name === 'expressSession')) ||
          (callee.type === 'CallExpression' &&
            callee.callee.type === 'MemberExpression' &&
            (callee.callee.property as BabelTypes.Identifier)?.name === 'session');

        if (!isSession) return;

        const optionsArg = path.node.arguments[0];
        const line = getNodeLine(path.node);

        if (!optionsArg || optionsArg.type !== 'ObjectExpression') return;

        // Check secret
        const secret = getObjectProperty(optionsArg, 'secret');
        if (!secret) {
          findings.push({
            ruleId: 'SESSION001',
            severity: 'critical',
            category: 'Sessions',
            title: 'Session Missing Secret',
            description: 'express-session configured without a secret',
            impact: 'Without a secret, session cookies cannot be signed and can be tampered with.',
            remediation: 'Set secret: process.env.SESSION_SECRET',
            references: sessionSecurityRule.references,
            filePath: context.filePath,
            line,
          });
        } else {
          const secretValue = getStringValue(secret);
          if (secretValue) {
            // Hardcoded secret
            findings.push({
              ruleId: 'SESSION001',
              severity: 'critical',
              category: 'Sessions',
              title: 'Hardcoded Session Secret',
              description: 'Session secret is hardcoded in source code',
              impact: 'Hardcoded secrets can be extracted from source, allowing session forgery.',
              remediation: 'Use: secret: process.env.SESSION_SECRET',
              references: sessionSecurityRule.references,
              filePath: context.filePath,
              line,
            });
          }
        }

        // Check saveUninitialized
        const saveUninitialized = getObjectProperty(optionsArg, 'saveUninitialized');
        if (!saveUninitialized || isBoolTrue(saveUninitialized)) {
          findings.push({
            ruleId: 'SESSION001',
            severity: 'medium',
            category: 'Sessions',
            title: 'Session saveUninitialized Should Be False',
            description: 'saveUninitialized: true can lead to session fixation and unnecessary session storage',
            impact: 'Creates sessions for unauthenticated users, enabling session fixation attacks.',
            remediation: 'Set saveUninitialized: false',
            references: sessionSecurityRule.references,
            filePath: context.filePath,
            line,
          });
        }

        // Check resave
        const resave = getObjectProperty(optionsArg, 'resave');
        if (!resave || isBoolTrue(resave)) {
          findings.push({
            ruleId: 'SESSION001',
            severity: 'low',
            category: 'Sessions',
            title: 'Session resave Should Be False',
            description: 'resave: true causes unnecessary session resaving',
            impact: 'Can cause race conditions and excessive storage operations.',
            remediation: 'Set resave: false',
            references: sessionSecurityRule.references,
            filePath: context.filePath,
            line,
          });
        }

        // Check cookie security
        const cookieProp = getObjectProperty(optionsArg, 'cookie');
        if (cookieProp && cookieProp.type === 'ObjectExpression') {
          const cookieHttpOnly = getObjectProperty(cookieProp, 'httpOnly');
          const cookieSecure = getObjectProperty(cookieProp, 'secure');

          if (isBoolFalse(cookieHttpOnly)) {
            findings.push({
              ruleId: 'SESSION001',
              severity: 'high',
              category: 'Sessions',
              title: 'Session Cookie Missing httpOnly',
              description: 'Session cookie has httpOnly: false',
              impact: 'Session cookies accessible via JavaScript can be stolen through XSS.',
              remediation: 'Set cookie: { httpOnly: true }',
              references: sessionSecurityRule.references,
              filePath: context.filePath,
              line,
            });
          }

          if (!cookieSecure || isBoolFalse(cookieSecure)) {
            findings.push({
              ruleId: 'SESSION001',
              severity: 'high',
              category: 'Sessions',
              title: 'Session Cookie Missing Secure Flag',
              description: 'Session cookie does not have secure: true',
              impact: 'Session cookies transmitted over HTTP can be intercepted.',
              remediation: 'Set cookie: { secure: process.env.NODE_ENV === "production" }',
              references: sessionSecurityRule.references,
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
