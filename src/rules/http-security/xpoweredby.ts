import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getNodeLine, getObjectProperty, isBoolFalse } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

export const xPoweredByRule: Rule = {
  id: 'HEADER001',
  severity: 'low',
  category: 'HTTP Security',
  title: 'X-Powered-By Header Enabled',
  description: 'Express exposes server technology via X-Powered-By header, aiding attacker fingerprinting',
  detectorType: 'ast',
  remediation: 'Disable via: app.disable("x-powered-by") or use helmet() which disables it automatically.',
  references: [
    {
      title: 'Express Security Best Practices',
      url: 'https://expressjs.com/en/advanced/best-practice-security.html#do-not-use-default-session-cookie-name',
    },
    {
      title: 'Helmet hidePoweredBy',
      url: 'https://helmetjs.github.io/#hidepoweredby',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const ast = context.ast as File;
    const findings: Finding[] = [];

    let disabledXPoweredBy = false;
    let hasHelmet = false;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        // Check for app.disable("x-powered-by")
        if (
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          callee.property.name === 'disable'
        ) {
          const arg = path.node.arguments[0];
          if (
            arg?.type === 'StringLiteral' &&
            arg.value.toLowerCase() === 'x-powered-by'
          ) {
            disabledXPoweredBy = true;
          }
        }

        // Check for helmet import/use
        if (
          callee.type === 'Identifier' && callee.name === 'helmet' ||
          (callee.type === 'MemberExpression' &&
           callee.property.type === 'Identifier' &&
           callee.property.name === 'use' &&
           path.node.arguments[0]?.type === 'CallExpression')
        ) {
          // Check if helmet() is passed as an argument
          const arg = path.node.arguments[0];
          if (
            arg?.type === 'CallExpression' &&
            arg.callee.type === 'Identifier' &&
            arg.callee.name === 'helmet'
          ) {
            hasHelmet = true;
          }
        }

        // Check for app.set("x-powered-by", false)
        if (
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          callee.property.name === 'set'
        ) {
          const [keyArg, valArg] = path.node.arguments;
          if (
            keyArg?.type === 'StringLiteral' &&
            keyArg.value.toLowerCase() === 'x-powered-by' &&
            valArg?.type === 'BooleanLiteral' &&
            !(valArg as BabelTypes.BooleanLiteral).value
          ) {
            disabledXPoweredBy = true;
          }
        }
      },
      ImportDeclaration(path: NodePath<BabelTypes.ImportDeclaration>) {
        if (path.node.source.value === 'helmet') {
          hasHelmet = true;
        }
      },
    });

    const isAppFile =
      context.filePath.endsWith('app.ts') ||
      context.filePath.endsWith('app.js') ||
      context.filePath.endsWith('server.ts') ||
      context.filePath.endsWith('server.js') ||
      context.filePath.endsWith('index.ts') ||
      context.filePath.endsWith('index.js');

    if (isAppFile && !disabledXPoweredBy && !hasHelmet) {
      findings.push({
        ruleId: 'HEADER001',
        severity: 'low',
        category: 'HTTP Security',
        title: 'X-Powered-By Header Enabled',
        description: 'X-Powered-By header is not disabled, exposing Express version information',
        impact: 'Reveals server technology to potential attackers, aiding in targeted vulnerability research.',
        remediation: 'Add: app.disable("x-powered-by") or use helmet()',
        references: xPoweredByRule.references,
        filePath: context.filePath,
      });
    }

    return findings;
  },
};
