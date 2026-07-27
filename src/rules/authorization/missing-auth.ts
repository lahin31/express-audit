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
];

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

        // Check if any middleware argument is an auth middleware
        const middlewareArgs = args.slice(1, -1); // between path and handler

        const hasAuthMiddleware = middlewareArgs.some(arg => {
          if (arg.type === 'Identifier') {
            return AUTH_MIDDLEWARE_PATTERNS.some(pattern =>
              arg.name.toLowerCase().includes(pattern.toLowerCase())
            );
          }
          if (arg.type === 'CallExpression') {
            const argSource = context.source.slice(arg.start || 0, arg.end || 0);
            return AUTH_MIDDLEWARE_PATTERNS.some(p => argSource.toLowerCase().includes(p.toLowerCase()));
          }
          return false;
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
