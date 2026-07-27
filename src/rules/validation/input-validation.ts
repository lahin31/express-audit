import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, findImports, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

/**
 * Detects direct use of req.body properties without validation middleware
 */
export const unsafeReqBodyRule: Rule = {
  id: 'VAL001',
  severity: 'medium',
  category: 'Input Validation',
  title: 'Unvalidated Request Body',
  description: 'req.body fields are used directly without input validation',
  detectorType: 'ast',
  remediation: 'Use a validation library like Zod, Joi, or express-validator to validate and sanitize input.',
  references: [
    {
      title: 'OWASP - Input Validation Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html',
    },
    {
      title: 'Express Validator',
      url: 'https://express-validator.github.io/docs/',
    },
    {
      title: 'Zod Documentation',
      url: 'https://zod.dev/',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const ast = context.ast as File;

    // Check if project uses a validation library
    const hasValidation =
      findImports(ast, 'zod') ||
      findImports(ast, 'joi') ||
      findImports(ast, '@hapi/joi') ||
      findImports(ast, 'express-validator') ||
      findImports(ast, 'yup') ||
      findImports(ast, 'ajv') ||
      findImports(ast, 'class-validator') ||
      findImports(ast, 'valibot');

    if (hasValidation) return [];

    const findings: Finding[] = [];
    const seenLines = new Set<number>();

    traverse(ast, {
      MemberExpression(path: NodePath<BabelTypes.MemberExpression>) {
        const { object, property } = path.node;

        // Detect req.body.fieldName usage
        if (
          object.type === 'MemberExpression' &&
          object.object.type === 'Identifier' &&
          object.object.name === 'req' &&
          object.property.type === 'Identifier' &&
          object.property.name === 'body' &&
          property.type === 'Identifier'
        ) {
          const line = getNodeLine(path.node);
          if (!seenLines.has(line)) {
            seenLines.add(line);
            findings.push({
              ruleId: 'VAL001',
              severity: 'medium',
              category: 'Input Validation',
              title: 'Unvalidated Request Body Access',
              description: `req.body.${property.name} accessed without validation middleware`,
              impact: 'Unvalidated input can lead to unexpected behavior, business logic bypasses, and security vulnerabilities.',
              remediation: 'Validate with Zod: const data = schema.parse(req.body)',
              references: unsafeReqBodyRule.references,
              filePath: context.filePath,
              line,
            });
          }
        }
      },
    });

    // Limit findings to 3 per file to avoid noise
    return findings.slice(0, 3);
  },
};

/**
 * Detects missing validation on specific dangerous operations
 */
export const unsafeQueryParamRule: Rule = {
  id: 'VAL002',
  severity: 'medium',
  category: 'Input Validation',
  title: 'Unvalidated Query Parameters',
  description: 'req.query parameters used directly in database queries or other sensitive operations',
  detectorType: 'ast',
  remediation: 'Validate and sanitize query parameters before use.',
  references: [
    {
      title: 'OWASP - Input Validation Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const ast = context.ast as File;
    const findings: Finding[] = [];
    const seenLines = new Set<number>();

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        // Look for DB query calls
        const isDbOperation =
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          ['query', 'execute', 'find', 'findOne', 'findAll', 'where'].includes(
            callee.property.name
          );

        if (!isDbOperation) return;

        // Check arguments for req.query usage
        const checkForQueryParam = (node: BabelTypes.Node): boolean => {
          if (
            node.type === 'MemberExpression' &&
            node.object.type === 'MemberExpression' &&
            node.object.object.type === 'Identifier' &&
            node.object.object.name === 'req' &&
            node.object.property.type === 'Identifier' &&
            node.object.property.name === 'query'
          ) {
            return true;
          }
          if (node.type === 'TemplateLiteral') {
            return (node as BabelTypes.TemplateLiteral).expressions.some(checkForQueryParam);
          }
          if (node.type === 'BinaryExpression') {
            return checkForQueryParam((node as BabelTypes.BinaryExpression).left) ||
                   checkForQueryParam((node as BabelTypes.BinaryExpression).right);
          }
          return false;
        };

        for (const arg of path.node.arguments) {
          if (checkForQueryParam(arg)) {
            const line = getNodeLine(path.node);
            if (!seenLines.has(line)) {
              seenLines.add(line);
              findings.push({
                ruleId: 'VAL002',
                severity: 'medium',
                category: 'Input Validation',
                title: 'Unvalidated Query Parameter in DB Operation',
                description: 'req.query value used directly in a database operation',
                impact: 'Unvalidated query parameters passed to database operations can lead to injection attacks or unexpected behavior.',
                remediation: 'Validate and sanitize query parameters before database use',
                references: unsafeQueryParamRule.references,
                filePath: context.filePath,
                line,
              });
            }
          }
        }
      },
    });

    return findings;
  },
};
