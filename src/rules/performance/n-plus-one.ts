import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

/**
 * DB method names that indicate a database query.
 * Covers Prisma, Mongoose, TypeORM, Sequelize, and raw drivers.
 */
const DB_QUERY_METHODS = new Set([
  // Prisma
  'findUnique', 'findFirst', 'findMany',
  'create', 'update', 'delete', 'upsert',
  'count', 'aggregate', 'groupBy',
  // Mongoose / generic ODM
  'findOne', 'findById', 'findByIdAndUpdate',
  'findOneAndUpdate', 'findOneAndDelete',
  'save', 'insertOne', 'updateOne', 'deleteOne',
  // Sequelize / TypeORM / generic
  'findAll', 'findAndCountAll',
  // Raw drivers
  'query', 'execute', 'run',
]);

/**
 * Returns true if the call expression looks like a DB query.
 * Matches: prisma.model.method(), Model.method(), db.query(), etc.
 */
function isDbCall(node: BabelTypes.CallExpression): boolean {
  const callee = node.callee;

  if (callee.type === 'MemberExpression') {
    const prop = callee.property;
    if (prop.type === 'Identifier' && DB_QUERY_METHODS.has(prop.name)) {
      return true;
    }

    // Prisma chained: prisma.user.findUnique — method is on a member of a member
    if (
      callee.object.type === 'MemberExpression' &&
      prop.type === 'Identifier' &&
      DB_QUERY_METHODS.has(prop.name)
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Returns true if the given AST node is (or is inside) a loop body.
 * Checks for: for, for...of, for...in, while, do...while
 */
function getEnclosingLoopDepth(path: NodePath): number {
  let depth = 0;
  let current = path.parentPath;

  while (current) {
    const type = current.node.type;
    if (
      type === 'ForStatement' ||
      type === 'ForOfStatement' ||
      type === 'ForInStatement' ||
      type === 'WhileStatement' ||
      type === 'DoWhileStatement'
    ) {
      depth++;
      break; // one level is enough to flag
    }

    // forEach / map callbacks
    if (type === 'ArrowFunctionExpression' || type === 'FunctionExpression') {
      const parent = current.parentPath;
      if (parent?.node.type === 'CallExpression') {
        const callee = (parent.node as BabelTypes.CallExpression).callee;
        if (
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          ['forEach', 'map', 'filter', 'reduce', 'flatMap', 'some', 'every', 'find'].includes(
            callee.property.name,
          )
        ) {
          depth++;
          break;
        }
      }
    }

    current = current.parentPath;
  }

  return depth;
}

export const nPlusOneQueryRule: Rule = {
  id: 'PERF001',
  severity: 'high',
  category: 'Performance',
  title: 'N+1 Query in Loop',
  description: 'A database query is executed inside a loop, causing one query per iteration (N+1 problem)',
  detectorType: 'ast',
  remediation: `Fetch all records in a single query outside the loop using IN / batch lookup.

Prisma example:
// ❌ N+1
for (const inv of invitations) {
  const user = await prisma.user.findUnique({ where: { email: inv.email } });
}

// ✅ Single query
const emails = invitations.map(i => i.email);
const users = await prisma.user.findMany({ where: { email: { in: emails } } });
const userMap = Object.fromEntries(users.map(u => [u.email, u]));`,
  references: [
    {
      title: 'OWASP API Security Top 10 2023 – API4: Unrestricted Resource Consumption',
      url: 'https://owasp.org/www-project-api-security/',
    },
    {
      title: 'Prisma Query Optimization and N+1',
      url: 'https://www.prisma.io/docs/guides/performance-and-optimization/query-optimization-performance',
    },
    {
      title: 'CWE-1176: Inefficient CPU Computation',
      url: 'https://cwe.mitre.org/data/definitions/1176.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;
    const seen = new Set<number>(); // deduplicate by line

    traverse(ast, {
      AwaitExpression(path: NodePath<BabelTypes.AwaitExpression>) {
        const arg = path.node.argument;

        // The awaited expression must be a DB call
        if (!arg || arg.type !== 'CallExpression') return;
        if (!isDbCall(arg as BabelTypes.CallExpression)) return;

        // It must be inside a loop
        const loopDepth = getEnclosingLoopDepth(path);
        if (loopDepth === 0) return;

        const line = getNodeLine(path.node);
        if (seen.has(line)) return;
        seen.add(line);

        // Get the method name for a clearer description
        const callee = (arg as BabelTypes.CallExpression).callee as BabelTypes.MemberExpression;
        const methodName =
          callee.property?.type === 'Identifier' ? callee.property.name : 'query';

        findings.push({
          ruleId: 'PERF001',
          severity: 'high',
          category: 'Performance',
          title: 'N+1 Query in Loop',
          description: `await ${methodName}() called inside a loop — each iteration executes a separate database query`,
          impact: 'With N records in the outer query, this produces N additional queries. For large datasets this degrades performance significantly and can exhaust database connections.',
          remediation: nPlusOneQueryRule.remediation,
          references: nPlusOneQueryRule.references,
          filePath: context.filePath,
          line,
        });
      },
    });

    return findings;
  },
};
