import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

/**
 * Returns true if the node is a user-controlled source:
 * req.body, req.query, req.params, req.headers
 * Also matches deeper access like req.body.field
 */
function isUserInput(node: BabelTypes.Node): boolean {
  if (node.type !== 'MemberExpression') return false;
  const mem = node as BabelTypes.MemberExpression;

  // Direct: req.body / req.query / req.params / req.headers
  if (
    mem.object.type === 'Identifier' &&
    (mem.object as BabelTypes.Identifier).name === 'req' &&
    mem.property.type === 'Identifier' &&
    ['body', 'query', 'params', 'headers'].includes(
      (mem.property as BabelTypes.Identifier).name,
    )
  ) return true;

  // Nested: req.body.field / req.query.name etc.
  return isUserInput(mem.object);
}

/**
 * Recursively checks whether a node IS user input or CONTAINS user input
 * (e.g. a template literal or binary expression that includes req.body).
 */
function containsUserInput(node: BabelTypes.Node): boolean {
  if (isUserInput(node)) return true;
  if (node.type === 'TemplateLiteral') {
    return (node as BabelTypes.TemplateLiteral).expressions.some(containsUserInput);
  }
  if (node.type === 'BinaryExpression') {
    const bin = node as BabelTypes.BinaryExpression;
    return containsUserInput(bin.left) || containsUserInput(bin.right);
  }
  return false;
}

/**
 * PP001 — Prototype Pollution via Object.assign / lodash.merge with user input
 *
 * Detects:
 *   Object.assign(target, req.body)
 *   _.merge(target, req.body)
 *   lodash.merge(target, req.body)
 *   merge(target, req.body)          — any local alias of a merge-like function
 */
export const prototypePollutionMergeRule: Rule = {
  id: 'PP001',
  severity: 'high',
  category: 'Input Validation',
  title: 'Prototype Pollution via Object Merge',
  description:
    'User-controlled input is spread or merged into an object without sanitization, ' +
    'enabling prototype pollution attacks.',
  detectorType: 'ast',
  remediation:
    'Validate and sanitize input before merging. Use a safe merge that strips ' +
    '__proto__, constructor, and prototype keys, or use structured cloning: ' +
    'JSON.parse(JSON.stringify(input)). Better yet, validate with Zod/Joi first.',
  references: [
    {
      title: 'OWASP – Prototype Pollution',
      url: 'https://owasp.org/www-community/vulnerabilities/Prototype_Pollution',
    },
    {
      title: 'OWASP Top 10 2021 – A03: Injection',
      url: 'https://owasp.org/Top10/A03_2021-Injection/',
    },
    {
      title: 'OWASP ASVS v4.0 – V5.1: Input Validation',
      url: 'https://owasp.org/www-project-application-security-verification-standard/',
    },
    {
      title: 'CWE-1321: Improperly Controlled Modification of Object Prototype',
      url: 'https://cwe.mitre.org/data/definitions/1321.html',
    },
    {
      title: 'Snyk – Prototype Pollution',
      url: 'https://learn.snyk.io/lesson/prototype-pollution/',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const seen = new Set<number>();
    const ast = context.ast as File;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;
        const args = path.node.arguments;

        // ── Pattern 1: Object.assign(target, userInput) ────────────────────
        const isObjectAssign =
          callee.type === 'MemberExpression' &&
          callee.object.type === 'Identifier' &&
          (callee.object as BabelTypes.Identifier).name === 'Object' &&
          callee.property.type === 'Identifier' &&
          (callee.property as BabelTypes.Identifier).name === 'assign';

        if (isObjectAssign && args.length >= 2) {
          // Any argument after the first (target) that contains user input
          const taintedArg = args.slice(1).find(a => containsUserInput(a));
          if (taintedArg) {
            const line = getNodeLine(path.node);
            if (!seen.has(line)) {
              seen.add(line);
              findings.push({
                ruleId: 'PP001',
                severity: 'high',
                category: 'Input Validation',
                title: 'Prototype Pollution via Object.assign',
                description:
                  'Object.assign() called with unsanitized user input — ' +
                  'an attacker can set __proto__ or constructor.prototype keys.',
                impact:
                  'Prototype pollution can override built-in Object properties, ' +
                  'leading to application logic bypass, privilege escalation, or RCE.',
                remediation:
                  'Validate input first: const safe = schema.parse(req.body); ' +
                  'Object.assign(target, safe). ' +
                  'Or strip dangerous keys before merging.',
                references: prototypePollutionMergeRule.references,
                filePath: context.filePath,
                line,
              });
            }
          }
        }

        // ── Pattern 2: _.merge / lodash.merge / merge(target, userInput) ───
        const isMergeCall = (() => {
          // _.merge(...)
          if (
            callee.type === 'MemberExpression' &&
            callee.property.type === 'Identifier' &&
            (callee.property as BabelTypes.Identifier).name === 'merge' &&
            callee.object.type === 'Identifier' &&
            ['_', 'lodash', 'merge'].includes(
              (callee.object as BabelTypes.Identifier).name,
            )
          ) return true;

          // merge(...) — bare function call named merge / deepMerge / deepExtend
          if (
            callee.type === 'Identifier' &&
            ['merge', 'deepMerge', 'deepExtend', 'extend', 'defaults'].includes(
              (callee as BabelTypes.Identifier).name,
            )
          ) return true;

          return false;
        })();

        if (isMergeCall && args.length >= 2) {
          const taintedArg = args.slice(1).find(a => containsUserInput(a));
          if (taintedArg) {
            const line = getNodeLine(path.node);
            if (!seen.has(line)) {
              seen.add(line);

              // Determine the function name for a clearer description
          const calleeName =
                callee.type === 'MemberExpression' &&
                callee.object.type === 'Identifier'
                  ? `${(callee.object as BabelTypes.Identifier).name}.merge`
                  : callee.type === 'Identifier'
                    ? (callee as BabelTypes.Identifier).name
                    : 'merge';

              findings.push({
                ruleId: 'PP001',
                severity: 'high',
                category: 'Input Validation',
                title: 'Prototype Pollution via Unsafe Merge',
                description:
                  `${calleeName}() called with unsanitized user input — ` +
                  'an attacker can inject __proto__ keys and pollute Object.prototype.',
                impact:
                  'Prototype pollution can override built-in Object properties, ' +
                  'leading to application logic bypass, privilege escalation, or RCE.',
                remediation:
                  'Validate input before merging: const safe = schema.parse(req.body); ' +
                  `${calleeName}(target, safe). ` +
                  'Use lodash@>=4.17.21 which has prototype pollution protections, ' +
                  'or use structured cloning: JSON.parse(JSON.stringify(input)).',
                references: prototypePollutionMergeRule.references,
                filePath: context.filePath,
                line,
              });
            }
          }
        }
      },

      // ── Pattern 3: obj[req.body.key] = value  (computed property assignment) ──
      AssignmentExpression(path: NodePath<BabelTypes.AssignmentExpression>) {
        const { left } = path.node;

        if (left.type !== 'MemberExpression') return;
        if (!(left as BabelTypes.MemberExpression).computed) return;

        const keyNode = (left as BabelTypes.MemberExpression).property;
        if (!containsUserInput(keyNode)) return;

        const line = getNodeLine(path.node);
        if (seen.has(line)) return;
        seen.add(line);

        findings.push({
          ruleId: 'PP001',
          severity: 'high',
          category: 'Input Validation',
          title: 'Prototype Pollution via Computed Property Assignment',
          description:
            'Object property is set using a user-controlled key — ' +
            'an attacker can assign to __proto__ and pollute Object.prototype.',
          impact:
            'Setting obj[userKey] = value where userKey is "__proto__" modifies ' +
            'the prototype chain for all objects, potentially bypassing security checks.',
          remediation:
            'Validate the key before assignment: ' +
            'const SAFE_KEYS = new Set([...]); ' +
            'if (SAFE_KEYS.has(key)) obj[key] = value; ' +
            'Or use a Map instead of a plain object.',
          references: prototypePollutionMergeRule.references,
          filePath: context.filePath,
          line,
        });
      },
    });

    return findings;
  },
};
