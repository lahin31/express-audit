# AUTHZ001 — Sensitive Route Missing Authentication

| Property     | Value           |
|--------------|-----------------|
| **ID**       | AUTHZ001        |
| **Severity** | ⚠️ High        |
| **Category** | Authorization   |
| **Detector** | AST             |

## Description

A `DELETE`, `PATCH`, or `PUT` route on a sensitive path (e.g. `/users`, `/accounts`, `/orders`) has no authentication middleware between the path and the handler.

## Why It Matters

State-changing endpoints without authentication allow unauthenticated users to modify or delete data. OWASP API Security 2023 ranks **Broken Object Level Authorization (API1)** and **Broken Authentication (API2)** as the top two API risks.

## Vulnerable Example

```typescript
// ❌ Anyone can delete any user
router.delete('/users/:id', async (req, res) => {
  await db.query('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.json({ deleted: true });
});

// ❌ Unauthenticated account update
router.patch('/accounts/:id', async (req, res) => {
  await Account.update(req.params.id, req.body);
  res.json({ ok: true });
});
```

## Secure Example

```typescript
import { authenticate } from '../middleware/auth.js';
import { requireOwnership } from '../middleware/authorization.js';

// ✅ Authenticate + verify the caller owns the resource
router.delete(
  '/users/:id',
  authenticate,           // 401 if no valid token
  requireOwnership,       // 403 if token userId !== params.id
  async (req, res) => {
    await User.delete(req.params.id);
    res.json({ deleted: true });
  },
);

router.patch(
  '/accounts/:id',
  authenticate,
  requireOwnership,
  async (req, res) => {
    const data = updateSchema.parse(req.body); // validate too
    await Account.update(req.params.id, data);
    res.json({ ok: true });
  },
);
```

```typescript
// middleware/authorization.ts
export function requireOwnership(req: Request, res: Response, next: NextFunction) {
  if (req.user.id !== req.params.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}
```

## Remediation

1. Add `authenticate` middleware to all `DELETE`, `PATCH`, and `PUT` routes.
2. Add **authorisation** middleware to verify the caller has permission to act on the specific resource (not just any authenticated user).
3. Adopt a consistent auth middleware pattern across the codebase — avoid ad-hoc `if (!req.user)` checks inline.

## References

- [OWASP API Security — Broken Object Level Authorization](https://owasp.org/www-project-api-security/)
- [OWASP — Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [Express Middleware Guide](https://expressjs.com/en/guide/using-middleware.html)
