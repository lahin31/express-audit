import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';
import { isEntryFile } from '../../core/is-entry-file.js';
import { parseFile } from '../../parser/index.js';
import { readFileSync, existsSync } from 'fs';

/**
 * ERR001 - Detects raw error objects sent directly to clients
 */
export const rawErrorResponseRule: Rule = {
  id: 'ERR001',
  severity: 'medium',
  category: 'Error Handling',
  title: 'Raw Error Object Returned to Client',
  description: 'An error object is being serialised and sent directly in an HTTP response',
  detectorType: 'ast',
  remediation:
    'Return a generic message to clients and log the full error server-side. Never expose internal error details in API responses.',
  references: [
    {
      title: 'OWASP – Improper Error Handling',
      url: 'https://owasp.org/www-community/Improper_Error_Handling',
    },
    {
      title: 'OWASP ASVS v4.0 – V7.4: Error Handling',
      url: 'https://owasp.org/www-project-application-security-verification-standard/',
    },
    {
      title: 'OWASP Top 10 2021 – A05: Security Misconfiguration',
      url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    },
    {
      title: 'CWE-209: Generation of Error Message Containing Sensitive Information',
      url: 'https://cwe.mitre.org/data/definitions/209.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        // res.json(...) / res.send(...)
        const isResOutput =
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          (callee.property.name === 'json' || callee.property.name === 'send') &&
          callee.object.type === 'Identifier' &&
          callee.object.name === 'res';

        if (!isResOutput) return;

        const arg = path.node.arguments[0];
        if (!arg) return;

        // res.json(err) or res.json(error) – bare error variable
        if (
          arg.type === 'Identifier' &&
          ['err', 'error', 'e', 'ex', 'exception'].includes(arg.name)
        ) {
          findings.push({
            ruleId: 'ERR001',
            severity: 'medium',
            category: 'Error Handling',
            title: 'Raw Error Object Returned to Client',
            description: `res.${(callee as BabelTypes.MemberExpression & { property: BabelTypes.Identifier }).property.name}(${arg.name}) sends the raw error to the client`,
            impact:
              'Exposes internal error messages, file paths, and stack information that aid attackers in targeted exploits.',
            remediation:
              'Replace with: res.status(500).json({ error: "Internal server error" }) and log the error server-side.',
            references: rawErrorResponseRule.references,
            filePath: context.filePath,
            line: getNodeLine(path.node),
          });
        }

        // res.json({ error: err, stack: err.stack, message: err.message, ... })
        if (arg.type === 'ObjectExpression') {
          for (const prop of arg.properties) {
            if (prop.type !== 'ObjectProperty') continue;
            const val = prop.value as BabelTypes.Node;

            // Matches any property whose value is err.stack / error.stack etc.
            if (
              val.type === 'MemberExpression' &&
              (val as BabelTypes.MemberExpression).property.type === 'Identifier' &&
              ((val as BabelTypes.MemberExpression).property as BabelTypes.Identifier).name === 'stack' &&
              (val as BabelTypes.MemberExpression).object.type === 'Identifier' &&
              ['err', 'error', 'e', 'ex', 'exception'].includes(
                ((val as BabelTypes.MemberExpression).object as BabelTypes.Identifier).name
              )
            ) {
              findings.push({
                ruleId: 'ERR001',
                severity: 'medium',
                category: 'Error Handling',
                title: 'Stack Trace Returned to Client',
                description: 'Error stack trace is included in the HTTP response body',
                impact:
                  'Stack traces reveal source file names, line numbers, and dependency versions, directly aiding attackers.',
                remediation: 'Remove the stack property from the response and log it server-side instead.',
                references: rawErrorResponseRule.references,
                filePath: context.filePath,
                line: getNodeLine(prop),
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

/**
 * ERR002 - Missing global error-handler middleware
 */
export const missingErrorHandlerRule: Rule = {
  id: 'ERR002',
  severity: 'medium',
  category: 'Error Handling',
  title: 'No Global Error-Handler Middleware',
  description:
    'No Express 4-argument error-handler middleware detected (err, req, res, next)',
  detectorType: 'ast',
  remediation:
    'Add a global error handler at the end of your middleware chain: app.use((err, req, res, next) => { ... })',
  references: [
    {
      title: 'Express Error Handling Guide',
      url: 'https://expressjs.com/en/guide/error-handling.html',
    },
    {
      title: 'OWASP ASVS v4.0 – V7.4: Error Handling',
      url: 'https://owasp.org/www-project-application-security-verification-standard/',
    },
    {
      title: 'OWASP Top 10 2021 – A05: Security Misconfiguration',
      url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    },
    {
      title: 'CWE-390: Detection of Error Condition Without Action',
      url: 'https://cwe.mitre.org/data/definitions/390.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];
    if (!isEntryFile(context.filePath, context.projectRoot, context.source)) return [];

    const ast = context.ast as File;

    // Names that strongly suggest an error-handling middleware even without
    // seeing the function body (e.g. app.use(globalErrorHandler))
    const ERROR_HANDLER_NAME_PATTERNS = [
      'error', 'err', 'errorhandler', 'errorhandling',
      'errormiddleware', 'handleerror', 'globalerror',
      'catcherror', 'errorcatch', 'onerror',
    ];

    // Identifiers passed to app.use() that look like named error handlers
    const namedHandlerCandidates: string[] = [];

    let hasErrorHandler = false;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        const isAppUse =
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          callee.property.name === 'use';

        if (!isAppUse) return;

        for (const arg of path.node.arguments) {
          // Case 1: inline 4-arg function — the most explicit form
          const isFourArgFn =
            (arg.type === 'ArrowFunctionExpression' ||
              arg.type === 'FunctionExpression') &&
            (arg as BabelTypes.ArrowFunctionExpression | BabelTypes.FunctionExpression)
              .params.length === 4;

          if (isFourArgFn) {
            hasErrorHandler = true;
            return;
          }

          // Case 2: named identifier passed to app.use()
          // e.g. app.use(globalErrorHandler), app.use(errorMiddleware)
          if (arg.type === 'Identifier') {
            const name = arg.name.toLowerCase();

            // Name itself signals error handling
            if (ERROR_HANDLER_NAME_PATTERNS.some(p => name.includes(p))) {
              hasErrorHandler = true;
              return;
            }

            // Collect for cross-file lookup below
            namedHandlerCandidates.push(arg.name);
          }
        }
      },
    });

    if (hasErrorHandler) return [];

    // Case 3: app.use(someFunction) where someFunction is defined elsewhere
    // and has 4 parameters. Scan the current file's source first (const/function decl),
    // then all project files.

    const isFourParamFunction = (fileAst: File, name: string): boolean => {
      let found = false;
      traverse(fileAst, {
        // const name = (err, req, res, next) => {}
        VariableDeclarator(path: NodePath<BabelTypes.VariableDeclarator>) {
          if (
            path.node.id.type === 'Identifier' &&
            path.node.id.name === name
          ) {
            const init = path.node.init;
            if (
              init &&
              (init.type === 'ArrowFunctionExpression' ||
                init.type === 'FunctionExpression') &&
              init.params.length === 4
            ) {
              found = true;
            }
          }
        },
        // function name(err, req, res, next) {}
        FunctionDeclaration(path: NodePath<BabelTypes.FunctionDeclaration>) {
          if (
            path.node.id?.name === name &&
            path.node.params.length === 4
          ) {
            found = true;
          }
        },
        // export function name / export const name
        ExportNamedDeclaration(path: NodePath<BabelTypes.ExportNamedDeclaration>) {
          const decl = path.node.declaration;
          if (!decl) return;
          if (
            decl.type === 'FunctionDeclaration' &&
            decl.id?.name === name &&
            decl.params.length === 4
          ) {
            found = true;
          }
        },
      });
      return found;
    };

    for (const candidateName of namedHandlerCandidates) {
      // Check current file first
      if (isFourParamFunction(ast as File, candidateName)) {
        return [];
      }

      // Check all other project files
      for (const filePath of context.allFiles) {
        if (filePath === context.filePath) continue;
        if (!existsSync(filePath)) continue;

        let src: string;
        try { src = readFileSync(filePath, 'utf-8'); } catch { continue; }
        if (!src.includes(candidateName)) continue;

        const { ast: fileAst } = parseFile(filePath);
        if (fileAst && isFourParamFunction(fileAst, candidateName)) {
          return [];
        }
      }
    }

    return [
      {
        ruleId: 'ERR002',
        severity: 'medium',
        category: 'Error Handling',
        title: 'No Global Error-Handler Middleware',
        description: 'No 4-argument error handler found in the application entry file',
        impact:
          'Without a catch-all error handler, unhandled errors may leak stack traces or crash the process.',
        remediation:
          "Add at the end of middleware: app.use((err, req, res, next) => { logger.error(err); res.status(500).json({ error: 'Internal server error' }); });",
        references: missingErrorHandlerRule.references,
        filePath: context.filePath,
      },
    ];
  },
};
