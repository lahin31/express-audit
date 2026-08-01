import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getStringValue, isProcessEnv, getNodeLine, getNodeColumn } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

export const jwtHardcodedRule: Rule = {
  id: 'JWT001',
  severity: 'critical',
  category: 'Authentication',
  title: 'Hardcoded JWT Secret',
  description: 'JWT secret is hardcoded in source code instead of using environment variables',
  detectorType: 'ast',
  remediation: 'Move JWT secrets to environment variables and use process.env.JWT_SECRET or a secure configuration management system.',
  references: [
    {
      title: 'OWASP - Use of Hard-coded Password',
      url: 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
    },
    {
      title: 'OWASP Top 10 2021 – A07: Identification and Authentication Failures',
      url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
    },
    {
      title: 'OWASP ASVS v4.0 – V2.10: Service Authentication',
      url: 'https://owasp.org/www-project-application-security-verification-standard/',
    },
    {
      title: 'RFC 8725 – JSON Web Token Best Current Practices',
      url: 'https://www.rfc-editor.org/rfc/rfc8725',
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
        
        // Check for jwt.sign() and jsonwebtoken.sign()
        let isJwtSign = false;
        if (callee.type === 'MemberExpression') {
          const obj = callee.object;
          const prop = callee.property;
          if (
            prop.type === 'Identifier' &&
            prop.name === 'sign' &&
            obj.type === 'Identifier' &&
            (obj.name === 'jwt' || obj.name === 'jsonwebtoken')
          ) {
            isJwtSign = true;
          }
        }

        if (isJwtSign) {
          // Second argument is the secret
          const secretArg = path.node.arguments[1];
          if (!secretArg) return;

          // Check if it's a hardcoded string (not process.env)
          const secretValue = getStringValue(secretArg);
          if (secretValue && !isProcessEnv(secretArg)) {
            findings.push({
              ruleId: 'JWT001',
              severity: 'critical',
              category: 'Authentication',
              title: 'Hardcoded JWT Secret',
              description: `JWT secret "${secretValue.substring(0, 20)}..." is hardcoded`,
              impact: 'Hardcoded secrets can be extracted from source code, allowing attackers to forge valid JWT tokens and impersonate users.',
              remediation: 'Use environment variables: jwt.sign(payload, process.env.JWT_SECRET)',
              references: jwtHardcodedRule.references,
              filePath: context.filePath,
              line: getNodeLine(secretArg),
              column: getNodeColumn(secretArg),
            });
          }
        }

        // Check for jwt.verify() with hardcoded secret
        let isJwtVerify = false;
        if (callee.type === 'MemberExpression') {
          const obj = callee.object;
          const prop = callee.property;
          if (
            prop.type === 'Identifier' &&
            prop.name === 'verify' &&
            obj.type === 'Identifier' &&
            (obj.name === 'jwt' || obj.name === 'jsonwebtoken')
          ) {
            isJwtVerify = true;
          }
        }

        if (isJwtVerify) {
          const secretArg = path.node.arguments[1];
          if (!secretArg) return;

          const secretValue = getStringValue(secretArg);
          if (secretValue && !isProcessEnv(secretArg)) {
            findings.push({
              ruleId: 'JWT001',
              severity: 'critical',
              category: 'Authentication',
              title: 'Hardcoded JWT Secret',
              description: `JWT verification secret "${secretValue.substring(0, 20)}..." is hardcoded`,
              impact: 'Hardcoded secrets can be extracted from source code, allowing attackers to forge valid JWT tokens.',
              remediation: 'Use environment variables: jwt.verify(token, process.env.JWT_SECRET)',
              references: jwtHardcodedRule.references,
              filePath: context.filePath,
              line: getNodeLine(secretArg),
              column: getNodeColumn(secretArg),
            });
          }
        }
      },
    });

    return findings;
  },
};
