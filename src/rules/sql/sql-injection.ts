import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

/**
 * Detects SQL injection risks in raw queries using string concatenation or template literals
 * with user-controlled input (req.body, req.query, req.params)
 */
export const sqlInjectionRule: Rule = {
  id: 'SQL001',
  severity: 'critical',
  category: 'SQL Security',
  title: 'SQL Injection Risk',
  description: 'Raw SQL queries are constructed using string concatenation with user input',
  detectorType: 'ast',
  remediation: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [req.params.id])',
  references: [
    {
      title: 'OWASP – SQL Injection',
      url: 'https://owasp.org/www-community/attacks/SQL_Injection',
    },
    {
      title: 'OWASP SQL Injection Prevention Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
    },
    {
      title: 'OWASP Top 10 2021 – A03: Injection',
      url: 'https://owasp.org/Top10/A03_2021-Injection/',
    },
    {
      title: 'OWASP ASVS v4.0 – V5.3: Output Encoding and Injection Prevention',
      url: 'https://owasp.org/www-project-application-security-verification-standard/',
    },
    {
      title: 'CWE-89: SQL Injection',
      url: 'https://cwe.mitre.org/data/definitions/89.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    /**
     * Check if a node accesses user-controlled values (req.body, req.query, req.params)
     */
    const isUserInput = (node: BabelTypes.Node): boolean => {
      if (node.type === 'MemberExpression') {
        const obj = node.object;
        if (obj.type === 'MemberExpression') {
          const innerObj = obj.object;
          if (innerObj.type === 'Identifier' && innerObj.name === 'req') {
            const innerProp = obj.property;
            if (innerProp.type === 'Identifier') {
              return ['body', 'query', 'params', 'headers'].includes(innerProp.name);
            }
          }
        }
      }
      return false;
    };

    /**
     * Recursively check if an expression tree contains user input
     */
    const containsUserInput = (node: BabelTypes.Node): boolean => {
      if (!node) return false;
      if (isUserInput(node)) return true;
      if (node.type === 'BinaryExpression') {
        return containsUserInput((node as BabelTypes.BinaryExpression).left) ||
               containsUserInput((node as BabelTypes.BinaryExpression).right);
      }
      if (node.type === 'TemplateLiteral') {
        return (node as BabelTypes.TemplateLiteral).expressions.some(containsUserInput);
      }
      return false;
    };

    /**
     * Check if a string contains SQL keywords
     */
    const looksLikeSQL = (str: string): boolean => {
      const sqlKeywords = /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|UNION|DROP|CREATE|ALTER|EXEC|EXECUTE)\b/i;
      return sqlKeywords.test(str);
    };

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        // Look for db.query(), connection.query(), pool.query(), client.query(), etc.
        const isDbQuery =
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          (callee.property.name === 'query' || 
           callee.property.name === 'execute' || 
           callee.property.name === 'run');

        if (!isDbQuery) return;

        const sqlArg = path.node.arguments[0];
        if (!sqlArg) return;

        // Check for template literal with user input
        if (sqlArg.type === 'TemplateLiteral') {
          if (containsUserInput(sqlArg)) {
            findings.push({
              ruleId: 'SQL001',
              severity: 'critical',
              category: 'SQL Security',
              title: 'SQL Injection via Template Literal',
              description: 'SQL query is constructed using a template literal with user input',
              impact: 'Attackers can inject arbitrary SQL, leading to data theft, modification, or database destruction.',
              remediation: 'Use parameterized queries: db.query("SELECT ... WHERE id = ?", [userInput])',
              references: sqlInjectionRule.references,
              filePath: context.filePath,
              line: getNodeLine(sqlArg),
            });
          }
        }

        // Check for string concatenation with user input
        if (sqlArg.type === 'BinaryExpression' && sqlArg.operator === '+') {
          if (containsUserInput(sqlArg)) {
            findings.push({
              ruleId: 'SQL001',
              severity: 'critical',
              category: 'SQL Security',
              title: 'SQL Injection via String Concatenation',
              description: 'SQL query is constructed by concatenating user input',
              impact: 'Attackers can inject arbitrary SQL, leading to data theft, modification, or database destruction.',
              remediation: 'Use parameterized queries: db.query("SELECT ... WHERE id = ?", [userInput])',
              references: sqlInjectionRule.references,
              filePath: context.filePath,
              line: getNodeLine(sqlArg),
            });
          }
        }
      },
    });

    return findings;
  },
};

/**
 * Detect use of Prisma's unsafe raw query methods
 */
export const prismaUnsafeRule: Rule = {
  id: 'SQL002',
  severity: 'high',
  category: 'SQL Security',
  title: 'Unsafe Prisma Raw Query',
  description: 'Prisma $queryRawUnsafe or $executeRawUnsafe used with potential SQL injection risk',
  detectorType: 'ast',
  remediation: 'Use $queryRaw with tagged template literals: prisma.$queryRaw`SELECT * FROM User WHERE id = ${id}`',
  references: [
    {
      title: 'Prisma – SQL Injection Prevention',
      url: 'https://www.prisma.io/docs/concepts/components/prisma-client/raw-database-access#sql-injection-prevention',
    },
    {
      title: 'OWASP Top 10 2021 – A03: Injection',
      url: 'https://owasp.org/Top10/A03_2021-Injection/',
    },
    {
      title: 'CWE-89: SQL Injection',
      url: 'https://cwe.mitre.org/data/definitions/89.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        if (
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          (callee.property.name === '$queryRawUnsafe' || callee.property.name === '$executeRawUnsafe')
        ) {
          const firstArg = path.node.arguments[0];
          
          findings.push({
            ruleId: 'SQL002',
            severity: 'high',
            category: 'SQL Security',
            title: 'Unsafe Prisma Raw Query',
            description: `${callee.property.name} bypasses Prisma's SQL injection protection`,
            impact: 'If user input is passed to this method without sanitization, SQL injection is possible.',
            remediation: 'Use $queryRaw or $executeRaw with tagged template literals instead.',
            references: prismaUnsafeRule.references,
            filePath: context.filePath,
            line: getNodeLine(path.node),
          });
        }
      },
    });

    return findings;
  },
};
