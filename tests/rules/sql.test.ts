import { describe, it, expect } from 'vitest';
import { sqlInjectionRule, prismaUnsafeRule } from '../../src/rules/sql/sql-injection.js';
import { createContext } from '../helpers.js';

// ---------------------------------------------------------------------------
// SQL001 – SQL injection
// ---------------------------------------------------------------------------
describe('SQL001 – SQL injection', () => {
  it('flags template literal with req.query in db.query()', () => {
    const ctx = createContext(`
      db.query(\`SELECT * FROM users WHERE name = '\${req.query.name}'\`);
    `);
    const findings = sqlInjectionRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('SQL001');
    expect(findings[0].severity).toBe('critical');
  });

  it('flags string concatenation with req.body', () => {
    const ctx = createContext(`
      db.query("SELECT * FROM users WHERE id = " + req.body.id);
    `);
    const findings = sqlInjectionRule.run(ctx);
    expect(findings).toHaveLength(1);
  });

  it('flags template literal with req.params', () => {
    const ctx = createContext(`
      db.execute(\`DELETE FROM items WHERE id = \${req.params.id}\`);
    `);
    expect(sqlInjectionRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag parameterised query', () => {
    const ctx = createContext(`
      db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
    `);
    expect(sqlInjectionRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag query with no user input', () => {
    const ctx = createContext(`
      db.query('SELECT * FROM config');
    `);
    expect(sqlInjectionRule.run(ctx)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// SQL002 – Prisma unsafe raw query
// ---------------------------------------------------------------------------
describe('SQL002 – Prisma $queryRawUnsafe', () => {
  it('flags prisma.$queryRawUnsafe()', () => {
    const ctx = createContext(`
      const users = await prisma.$queryRawUnsafe('SELECT * FROM users WHERE id = ' + id);
    `);
    const findings = prismaUnsafeRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('SQL002');
  });

  it('flags prisma.$executeRawUnsafe()', () => {
    const ctx = createContext(
      "await prisma.$executeRawUnsafe('DELETE FROM sessions WHERE token = ' + token);",
    );
    expect(prismaUnsafeRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag prisma.$queryRaw tagged template', () => {
    const ctx = createContext(`
      const users = await prisma.$queryRaw\`SELECT * FROM users WHERE id = \${id}\`;
    `);
    expect(prismaUnsafeRule.run(ctx)).toHaveLength(0);
  });
});
