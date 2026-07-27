import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

/**
 * Detects password comparisons that don't use a hashing library
 * e.g., user.password === inputPassword (plaintext comparison)
 */
export const plaintextPasswordRule: Rule = {
  id: 'AUTH002',
  severity: 'critical',
  category: 'Authentication',
  title: 'Plaintext Password Comparison',
  description: 'Passwords are being compared directly without using a secure hashing function',
  detectorType: 'ast',
  remediation: 'Use bcrypt.compare() or argon2.verify() instead of direct string comparison for passwords.',
  references: [
    {
      title: 'OWASP - Password Storage Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    // Look for patterns like: user.password === req.body.password
    traverse(ast, {
      BinaryExpression(path: NodePath<BabelTypes.BinaryExpression>) {
        const { left, right, operator } = path.node;
        if (operator !== '===' && operator !== '==' && operator !== '!==' && operator !== '!=') {
          return;
        }

        const isPasswordNode = (node: BabelTypes.Node): boolean => {
          if (node.type === 'MemberExpression') {
            const prop = node.property;
            if (prop.type === 'Identifier') {
              const name = prop.name.toLowerCase();
              return name === 'password' || name === 'pass' || name === 'passwd' || name === 'pwd';
            }
          }
          return false;
        };

        if (isPasswordNode(left) || isPasswordNode(right)) {
          findings.push({
            ruleId: 'AUTH002',
            severity: 'critical',
            category: 'Authentication',
            title: 'Plaintext Password Comparison',
            description: 'Passwords appear to be compared directly without hashing',
            impact: 'Storing or comparing plaintext passwords allows credential theft from database breaches.',
            remediation: 'Use: await bcrypt.compare(inputPassword, storedHash)',
            references: plaintextPasswordRule.references,
            filePath: context.filePath,
            line: getNodeLine(path.node),
          });
        }
      },
    });

    return findings;
  },
};
