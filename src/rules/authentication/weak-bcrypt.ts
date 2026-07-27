import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

export const weakBcryptRule: Rule = {
  id: 'AUTH001',
  severity: 'high',
  category: 'Authentication',
  title: 'Weak bcrypt Cost Factor',
  description: 'bcrypt is used with a cost factor lower than 12, which is insufficient for production',
  detectorType: 'ast',
  remediation: 'Use a minimum cost factor of 12: bcrypt.hash(password, 12)',
  references: [
    {
      title: 'OWASP Password Storage Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',
    },
    {
      title: 'bcrypt documentation',
      url: 'https://www.npmjs.com/package/bcrypt',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        // Check for bcrypt.hash() and bcrypt.hashSync()
        let isBcryptHash = false;
        if (callee.type === 'MemberExpression') {
          const obj = callee.object;
          const prop = callee.property;
          if (
            prop.type === 'Identifier' &&
            (prop.name === 'hash' || prop.name === 'hashSync') &&
            obj.type === 'Identifier' &&
            (obj.name === 'bcrypt' || obj.name === 'bcryptjs')
          ) {
            isBcryptHash = true;
          }
        }

        if (!isBcryptHash) return;

        // Second argument is the salt rounds
        const saltArg = path.node.arguments[1];
        if (!saltArg) {
          findings.push({
            ruleId: 'AUTH001',
            severity: 'high',
            category: 'Authentication',
            title: 'Missing bcrypt Cost Factor',
            description: 'bcrypt.hash called without a cost factor',
            impact: 'Passwords may be hashed with the default cost, which may be too low.',
            remediation: 'Explicitly set the cost factor: bcrypt.hash(password, 12)',
            references: weakBcryptRule.references,
            filePath: context.filePath,
            line: getNodeLine(path.node),
          });
          return;
        }

        if (saltArg.type === 'NumericLiteral') {
          const rounds = saltArg.value;
          if (rounds < 12) {
            findings.push({
              ruleId: 'AUTH001',
              severity: 'high',
              category: 'Authentication',
              title: 'Weak bcrypt Cost Factor',
              description: `bcrypt cost factor is ${rounds}, which is below the recommended minimum of 12`,
              impact: 'A low cost factor allows attackers to brute-force password hashes much faster.',
              remediation: `Increase cost factor to at least 12: bcrypt.hash(password, 12)`,
              references: weakBcryptRule.references,
              filePath: context.filePath,
              line: getNodeLine(saltArg),
            });
          }
        }
      },
    });

    return findings;
  },
};
