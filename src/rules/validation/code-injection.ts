import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

/**
 * Returns true if the node is — or descends from — a user-controlled source:
 * req.body, req.query, req.params, req.headers (and nested field access on those)
 */
function isUserInput(node: BabelTypes.Node): boolean {
  if (node.type !== 'MemberExpression') return false;
  const mem = node as BabelTypes.MemberExpression;

  // req.body / req.query / req.params / req.headers
  if (
    mem.object.type === 'Identifier' &&
    (mem.object as BabelTypes.Identifier).name === 'req' &&
    mem.property.type === 'Identifier' &&
    ['body', 'query', 'params', 'headers'].includes(
      (mem.property as BabelTypes.Identifier).name,
    )
  ) return true;

  // req.body.field / req.query.name etc.
  return isUserInput(mem.object);
}

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
 * INJECT001 – Code Injection via eval / new Function / vm.runInNewContext
 *
 * Detects user-controlled input passed to dynamic code execution sinks:
 *   eval(req.body.code)
 *   new Function(req.query.fn)
 *   new Function('x', req.body.expr)
 *   vm.runInNewContext(req.body.script)
 *   vm.runInThisContext(req.query.code)
 *   vm.Script(req.body.src)
 */
export const codeInjectionRule: Rule = {
  id: 'INJECT001',
  severity: 'critical',
  category: 'Input Validation',
  title: 'Code Injection via eval or new Function',
  description:
    'User-controlled input is passed to a dynamic code execution sink ' +
    '(eval, new Function, or Node.js vm module), enabling remote code execution.',
  detectorType: 'ast',
  remediation:
    'Never pass user input to eval(), new Function(), or vm.runInNewContext(). ' +
    'If dynamic evaluation is genuinely required, use a sandboxed interpreter ' +
    'such as isolated-vm, or evaluate the need entirely — most use cases can be ' +
    'replaced with a lookup table, JSON schema validation, or a safe expression ' +
    'parser like expr-eval.',
  references: [
    {
      title: 'OWASP Top 10 2021 – A03: Injection',
      url: 'https://owasp.org/Top10/A03_2021-Injection/',
    },
    {
      title: 'OWASP ASVS v4.0 – V5.2: Sanitization and Sandboxing',
      url: 'https://owasp.org/www-project-application-security-verification-standard/',
    },
    {
      title: 'OWASP Code Injection',
      url: 'https://owasp.org/www-community/attacks/Code_Injection',
    },
    {
      title: 'CWE-94: Improper Control of Generation of Code (Code Injection)',
      url: 'https://cwe.mitre.org/data/definitions/94.html',
    },
    {
      title: 'CWE-95: Improper Neutralization of Directives in eval()',
      url: 'https://cwe.mitre.org/data/definitions/95.html',
    },
    {
      title: 'Node.js vm Module Documentation',
      url: 'https://nodejs.org/api/vm.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const seen = new Set<number>();
    const ast = context.ast as File;

    const push = (line: number, sink: string) => {
      if (seen.has(line)) return;
      seen.add(line);
      findings.push({
        ruleId: 'INJECT001',
        severity: 'critical',
        category: 'Input Validation',
        title: 'Code Injection via eval or new Function',
        description: `User-controlled input passed to ${sink} enables arbitrary code execution`,
        impact:
          'An attacker can execute arbitrary JavaScript on the server, leading to ' +
          'full server compromise, data exfiltration, or lateral movement.',
        remediation: codeInjectionRule.remediation,
        references: codeInjectionRule.references,
        filePath: context.filePath,
        line,
      });
    };

    traverse(ast, {
      // ── eval(userInput) ───────────────────────────────────────────────────
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;
        const args = path.node.arguments;

        // eval(...)
        if (
          callee.type === 'Identifier' &&
          (callee as BabelTypes.Identifier).name === 'eval' &&
          args.length >= 1 &&
          containsUserInput(args[0])
        ) {
          push(getNodeLine(path.node), 'eval()');
          return;
        }

        // vm.runInNewContext(code, ...) / vm.runInThisContext(code) / vm.Script(code)
        if (
          callee.type === 'MemberExpression' &&
          callee.object.type === 'Identifier' &&
          (callee.object as BabelTypes.Identifier).name === 'vm' &&
          callee.property.type === 'Identifier' &&
          ['runInNewContext', 'runInThisContext', 'runInContext', 'compileFunction'].includes(
            (callee.property as BabelTypes.Identifier).name,
          ) &&
          args.length >= 1 &&
          containsUserInput(args[0])
        ) {
          const method = (callee.property as BabelTypes.Identifier).name;
          push(getNodeLine(path.node), `vm.${method}()`);
        }
      },

      // ── new Function(..., userInput) ──────────────────────────────────────
      NewExpression(path: NodePath<BabelTypes.NewExpression>) {
        const callee = path.node.callee;
        const args = path.node.arguments;

        if (
          callee.type === 'Identifier' &&
          (callee as BabelTypes.Identifier).name === 'Function' &&
          args.length >= 1 &&
          args.some(a => containsUserInput(a))
        ) {
          push(getNodeLine(path.node), 'new Function()');
        }

        // new vm.Script(userInput)
        if (
          callee.type === 'MemberExpression' &&
          callee.object.type === 'Identifier' &&
          (callee.object as BabelTypes.Identifier).name === 'vm' &&
          callee.property.type === 'Identifier' &&
          (callee.property as BabelTypes.Identifier).name === 'Script' &&
          args.length >= 1 &&
          containsUserInput(args[0])
        ) {
          push(getNodeLine(path.node), 'new vm.Script()');
        }
      },
    });

    return findings;
  },
};
