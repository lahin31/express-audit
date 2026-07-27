import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getObjectProperty, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

export const jwtNoExpiryRule: Rule = {
  id: 'JWT002',
  severity: 'high',
  category: 'Authentication',
  title: 'JWT Missing Expiration',
  description: 'JWT tokens are signed without an expiration time (expiresIn option missing)',
  detectorType: 'ast',
  remediation: 'Always set a token expiration: jwt.sign(payload, secret, { expiresIn: "15m" })',
  references: [
    {
      title: 'OWASP - JWT Security Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html',
    },
    {
      title: 'RFC 7519 - JWT Claims',
      url: 'https://tools.ietf.org/html/rfc7519#section-4.1.4',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        // Check for jwt.sign()
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

        if (!isJwtSign) return;

        // Third argument is options
        const optionsArg = path.node.arguments[2];
        
        // No options at all
        if (!optionsArg) {
          findings.push({
            ruleId: 'JWT002',
            severity: 'high',
            category: 'Authentication',
            title: 'JWT Missing Expiration',
            description: 'JWT token is created without an expiration time',
            impact: 'Tokens without expiration are valid forever, allowing stolen tokens to be used indefinitely.',
            remediation: 'Set expiresIn: jwt.sign(payload, secret, { expiresIn: "15m" })',
            references: jwtNoExpiryRule.references,
            filePath: context.filePath,
            line: getNodeLine(path.node),
          });
          return;
        }

        // Options is an object - check if expiresIn is set
        if (optionsArg.type === 'ObjectExpression') {
          const expiresIn = getObjectProperty(optionsArg, 'expiresIn');
          const exp = getObjectProperty(optionsArg, 'exp');
          
          if (!expiresIn && !exp) {
            findings.push({
              ruleId: 'JWT002',
              severity: 'high',
              category: 'Authentication',
              title: 'JWT Missing Expiration',
              description: 'JWT token is created without expiresIn option',
              impact: 'Tokens without expiration are valid forever, allowing stolen tokens to be used indefinitely.',
              remediation: 'Set expiresIn: jwt.sign(payload, secret, { expiresIn: "15m" })',
              references: jwtNoExpiryRule.references,
              filePath: context.filePath,
              line: getNodeLine(optionsArg),
            });
          }
        }
      },
    });

    return findings;
  },
};
