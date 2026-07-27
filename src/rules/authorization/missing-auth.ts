import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getStringValue, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

const AUTH_MIDDLEWARE_PATTERNS = [
  'authenticate',
  'isAuthenticated',
  'requireAuth',
  'authMiddleware',
  'verifyToken',
  'checkAuth',
  'passport.authenticate',
  'ensureLoggedIn',
  'protect',
  'requireLogin',
  'requireUser',
  'isLoggedIn',
  'withAuth',
  // common custom naming patterns
  'auth',
  'guard',
  'middleware',
  'verify',
  'token',
  'session',
  'permission',
];

/**
 * Extract all identifier names from a middleware argument.
 * Handles: identifier, callExpression, arrayExpression of the above.
 */
function extractMiddlewareNames(arg: BabelTypes.Node, source: string): string[] {
  // Plain identifier: authenticate
  if (arg.type === 'Identifier') return [arg.name];

  // Call expression: passport.authenticate(), verifyToken()
  if (arg.type === 'CallExpression') {
    return [source.slice(arg.start ?? 0, arg.end ?? 0)];
  }

  // Array of middleware: [auth, requireRole('admin')]
  if (arg.type === 'ArrayExpression') {
    return (arg as BabelTypes.ArrayExpression).elements.flatMap(el => {
      if (!el) return [];
      return extractMiddlewareNames(el, source);
    });
  }

  return [];
}

/**
 * Returns true if the given name or source snippet looks like an auth middleware.
 * Matches both explicit patterns and heuristic signals (checks token/authorization/cookie).
 */
function looksLikeAuthMiddleware(nameOrSource: string): boolean {
  const lower = nameOrSource.toLowerCase();

  // Match known auth-related keywords in the identifier name
  if (AUTH_MIDDLEWARE_PATTERNS.some(p => lower.includes(p.toLowerCase()))) return true;

  // Heuristic: the source snippet accesses authorization header, verifies a token,
  // or reads an auth cookie — strong signal it is an auth middleware even with a
  // custom name like authSuperAdminOrAdminMiddleware
  if (
    lower.includes('authorization') ||
    lower.includes('verifytoken') ||
    lower.includes('req.cookies') ||
    lower.includes('bearer') ||
    lower.includes('decoded') ||
    lower.includes('req.user') ||
    lower.includes('req.admin') ||
    lower.includes('req.super_admin')
  ) return true;

  return false;
}

const SENSITIVE_HTTP_METHODS = ['delete', 'patch', 'put'];

const SENSITIVE_ROUTE_PATTERNS = [
  '/admin',
  '/users',
  '/accounts',
  '/orders',
  '/payment',
  '/profile',
  '/settings',
  '/api/v',
];

/**
 * Detect DELETE/PATCH/PUT routes without authentication middleware
 */
export const missingAuthMiddlewareRule: Rule = {
  id: 'AUTHZ001',
  severity: 'high',
  category: 'Authorization',
  title: 'Sensitive Route Missing Authentication',
  description: 'DELETE, PATCH, or PUT routes on sensitive paths lack authentication middleware',
  detectorType: 'ast',
  remediation: 'Add authentication middleware to all state-changing routes: router.delete("/users/:id", authenticate, handler)',
  references: [
    {
      title: 'OWASP - Broken Access Control',
      url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
    },
    {
      title: 'OWASP - Authentication Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        if (callee.type !== 'MemberExpression') return;
        if (callee.property.type !== 'Identifier') return;

        const method = callee.property.name.toLowerCase();
        if (!SENSITIVE_HTTP_METHODS.includes(method)) return;

        const args = path.node.arguments;
        if (args.length < 2) return;

        // First arg is the route path
        const routeArg = args[0];
        const routePath = getStringValue(routeArg);
        if (!routePath) return;

        // Check if route path is sensitive
        const isSensitivePath = SENSITIVE_ROUTE_PATTERNS.some(p => routePath.includes(p));
        if (!isSensitivePath) return;

        // Check if any middleware argument is an auth middleware.
        // Handles: plain identifier, call expression, array of middleware.
        const middlewareArgs = args.slice(1, -1); // between path and handler

        // Also consider the last arg if there are only 2 total (path + handler)
        // because some patterns are: router.patch(path, [middleware], handler)
        // where slice(1,-1) would pick up the array correctly.
        // But if args.length === 2, there are no middleware args — genuinely missing.
        const hasAuthMiddleware = middlewareArgs.some(arg => {
          const names = extractMiddlewareNames(arg, context.source);
          return names.some(n => {
            // Check name alone first (fast path)
            if (looksLikeAuthMiddleware(n)) return true;
            // For identifiers, also look up the variable definition in the source
            // to check if the function body contains auth signals
            if (arg.type === 'Identifier' || arg.type === 'ArrayExpression') {
              const varName = n.trim();
              // Simple heuristic: search for `const varName` or `function varName`
              // and check the surrounding ~500 chars for auth signals
              const defIndex = context.source.indexOf(`const ${varName}`);
              if (defIndex !== -1) {
                const snippet = context.source.slice(defIndex, defIndex + 600);
                if (looksLikeAuthMiddleware(snippet)) return true;
              }
              const fnIndex = context.source.indexOf(`function ${varName}`);
              if (fnIndex !== -1) {
                const snippet = context.source.slice(fnIndex, fnIndex + 600);
                if (looksLikeAuthMiddleware(snippet)) return true;
              }
            }
            return false;
          });
        });

        if (!hasAuthMiddleware) {
          findings.push({
            ruleId: 'AUTHZ001',
            severity: 'high',
            category: 'Authorization',
            title: 'Sensitive Route Missing Authentication',
            description: `${method.toUpperCase()} ${routePath} has no authentication middleware`,
            impact: 'Unauthenticated users can modify or delete resources, leading to unauthorized data modification.',
            remediation: `Add auth middleware: router.${method}("${routePath}", authenticate, handler)`,
            references: missingAuthMiddlewareRule.references,
            filePath: context.filePath,
            line: getNodeLine(path.node),
          });
        }
      },
    });

    return findings;
  },
};

/**
 * Detect admin routes without protection
 */
export const adminRouteUnprotectedRule: Rule = {
  id: 'AUTHZ002',
  severity: 'critical',
  category: 'Authorization',
  title: 'Admin Route Unprotected',
  description: 'Admin endpoints are accessible without authorization middleware',
  detectorType: 'ast',
  remediation: 'Add both authentication and role-based authorization to all admin routes.',
  references: [
    {
      title: 'OWASP - Access Control Design Principles',
      url: 'https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    const adminPatterns = ['/admin', '/superuser', '/internal', '/management', '/backoffice'];
    const rbacPatterns = ['admin', 'role', 'permission', 'authorize', 'isAdmin', 'hasRole', 'requireRole', 'checkPermission'];

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        if (callee.type !== 'MemberExpression') return;
        if (callee.property.type !== 'Identifier') return;

        const method = callee.property.name.toLowerCase();
        if (!['get', 'post', 'put', 'patch', 'delete', 'use', 'all'].includes(method)) return;

        const args = path.node.arguments;
        if (args.length < 2) return;

        const routeArg = args[0];
        const routePath = getStringValue(routeArg);
        if (!routePath) return;

        const isAdminRoute = adminPatterns.some(p => routePath.includes(p));
        if (!isAdminRoute) return;

        // Check all middleware and handler args for RBAC patterns
        const allArgsSource = args
          .slice(1)
          .map(a => context.source.slice(a.start || 0, a.end || 0))
          .join(' ');

        const hasRBAC = rbacPatterns.some(p => allArgsSource.toLowerCase().includes(p.toLowerCase()));

        if (!hasRBAC) {
          findings.push({
            ruleId: 'AUTHZ002',
            severity: 'critical',
            category: 'Authorization',
            title: 'Admin Route Unprotected',
            description: `Admin route ${method.toUpperCase()} ${routePath} lacks authorization middleware`,
            impact: 'Unprotected admin routes can be accessed by any authenticated (or even unauthenticated) user.',
            remediation: `Add auth + RBAC: router.${method}("${routePath}", authenticate, requireRole("admin"), handler)`,
            references: adminRouteUnprotectedRule.references,
            filePath: context.filePath,
            line: getNodeLine(path.node),
          });
        }
      },
    });

    return findings;
  },
};
