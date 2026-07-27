import { describe, it, expect } from 'vitest';
import { missingAuthMiddlewareRule, adminRouteUnprotectedRule } from '../../src/rules/authorization/missing-auth.js';
import { createContext } from '../helpers.js';

describe('AUTHZ001 – Sensitive route missing auth', () => {
  it('flags DELETE /users/:id without auth middleware', () => {
    const ctx = createContext(`
      router.delete('/users/:id', async (req, res) => {
        await db.delete(req.params.id);
        res.json({ ok: true });
      });
    `);
    const findings = missingAuthMiddlewareRule.run(ctx);
    expect(findings.some(f => f.ruleId === 'AUTHZ001')).toBe(true);
  });

  it('does not flag DELETE route with authenticate middleware', () => {
    const ctx = createContext(`
      router.delete('/users/:id', authenticate, async (req, res) => {
        res.json({ ok: true });
      });
    `);
    expect(missingAuthMiddlewareRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag route with middleware passed as an array', () => {
    const ctx = createContext(`
      router.patch('/users/:user_id', [authSuperAdminOrAdminMiddleware], superAdminController.editUser);
    `);
    expect(missingAuthMiddlewareRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag route where array middleware name contains auth signal', () => {
    // Real-world pattern: custom middleware with auth in the name
    const ctx = createContext(`
      router.patch('/users/:id', [checkAdminPermission], handler);
    `);
    expect(missingAuthMiddlewareRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag route where middleware definition in source contains auth signals', () => {
    const ctx = createContext(
      `const myCustomGuard = async (req, res, next) => {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(403).json({ message: 'Access denied' });
        const decoded = await verifyToken(token, process.env.SECRET);
        req.user = decoded;
        next();
      };
      router.patch('/users/:id', myCustomGuard, handler);`,
    );
    expect(missingAuthMiddlewareRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag GET routes (read-only)', () => {
    const ctx = createContext(`
      router.get('/users', async (req, res) => {
        res.json([]);
      });
    `);
    expect(missingAuthMiddlewareRule.run(ctx)).toHaveLength(0);
  });

  it('flags PATCH /accounts/:id without auth', () => {
    const ctx = createContext(`
      router.patch('/accounts/:id', async (req, res) => {
        await db.update(req.params.id, req.body);
        res.json({ ok: true });
      });
    `);
    const findings = missingAuthMiddlewareRule.run(ctx);
    expect(findings.some(f => f.ruleId === 'AUTHZ001')).toBe(true);
  });
});

describe('AUTHZ002 – Admin route unprotected', () => {
  it('flags GET /admin/users without role check', () => {
    const ctx = createContext(`
      app.get('/admin/users', authenticate, async (req, res) => {
        res.json(users);
      });
    `);
    const findings = adminRouteUnprotectedRule.run(ctx);
    expect(findings.some(f => f.ruleId === 'AUTHZ002')).toBe(true);
  });

  it('does not flag /admin route with isAdmin middleware', () => {
    const ctx = createContext(`
      app.get('/admin/users', authenticate, isAdmin, async (req, res) => {
        res.json(users);
      });
    `);
    expect(adminRouteUnprotectedRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag /admin route with requireRole middleware', () => {
    const ctx = createContext(`
      app.get('/admin/dashboard', authenticate, requireRole('admin'), handler);
    `);
    expect(adminRouteUnprotectedRule.run(ctx)).toHaveLength(0);
  });
});
