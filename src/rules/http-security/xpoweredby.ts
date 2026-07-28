import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getObjectProperty, isBoolFalse, findImports } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';
import { isEntryFile } from '../../core/is-entry-file.js';
import { parseFile } from '../../parser/index.js';
import { readFileSync, existsSync } from 'fs';

/**
 * Check if the given AST disables X-Powered-By or uses helmet.
 */
function astDisablesXPoweredBy(ast: File): boolean {
  let disabled = false;

  traverse(ast, {
    // app.disable("x-powered-by")
    CallExpression(path: NodePath<BabelTypes.CallExpression>) {
      const callee = path.node.callee;

      if (
        callee.type === 'MemberExpression' &&
        callee.property.type === 'Identifier' &&
        callee.property.name === 'disable'
      ) {
        const arg = path.node.arguments[0];
        if (arg?.type === 'StringLiteral' && arg.value.toLowerCase() === 'x-powered-by') {
          disabled = true;
        }
      }

      // app.set("x-powered-by", false)
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
          disabled = true;
        }
      }
    },
  });

  return disabled;
}

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
    if (!isEntryFile(context.filePath, context.projectRoot, context.source)) return [];

    // 1. Check the entry file itself
    if (findImports(context.ast as File, 'helmet')) return [];
    if (astDisablesXPoweredBy(context.ast as File)) return [];

    // 2. Scan all project files — helmet or x-powered-by disable may be in a
    //    dedicated middleware setup file (e.g. middlewares/default.ts)
    for (const filePath of context.allFiles) {
      if (filePath === context.filePath) continue;
      if (!existsSync(filePath)) continue;

      let src: string;
      try { src = readFileSync(filePath, 'utf-8'); } catch { continue; }

      // Fast filter — only parse if file mentions helmet or x-powered-by
      if (!src.includes('helmet') && !src.includes('x-powered-by')) continue;

      const { ast } = parseFile(filePath);
      if (!ast) continue;

      if (findImports(ast, 'helmet') || astDisablesXPoweredBy(ast)) return [];
    }

    return [{
      ruleId: 'HEADER001',
      severity: 'low',
      category: 'HTTP Security',
      title: 'X-Powered-By Header Enabled',
      description: 'X-Powered-By header is not disabled in the project',
      impact: 'Reveals server technology to potential attackers, aiding in targeted vulnerability research.',
      remediation: 'Add: app.disable("x-powered-by") or use helmet()',
      references: xPoweredByRule.references,
      filePath: context.filePath,
    }];
  },
};
