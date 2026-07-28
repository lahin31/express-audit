import { describe, it, expect } from 'vitest';
import { nPlusOneQueryRule } from '../../src/rules/performance/n-plus-one.js';
import { createContext } from '../helpers.js';

describe('PERF001 – N+1 Query in Loop', () => {
  it('flags await prisma.findUnique inside a for...of loop', () => {
    const ctx = createContext(`
      for (const invitation of invitations) {
        const user = await prisma.user.findUnique({ where: { email: invitation.email } });
      }
    `);
    const findings = nPlusOneQueryRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('PERF001');
    expect(findings[0].severity).toBe('high');
  });

  it('flags await db.query inside a for loop', () => {
    const ctx = createContext(`
      for (let i = 0; i < ids.length; i++) {
        const row = await db.query('SELECT * FROM users WHERE id = ?', [ids[i]]);
      }
    `);
    expect(nPlusOneQueryRule.run(ctx)).toHaveLength(1);
  });

  it('flags await Model.findOne inside forEach callback', () => {
    const ctx = createContext(`
      items.forEach(async (item) => {
        const record = await Model.findOne({ _id: item.id });
      });
    `);
    expect(nPlusOneQueryRule.run(ctx)).toHaveLength(1);
  });

  it('flags await inside a map callback', () => {
    const ctx = createContext(`
      const results = await Promise.all(ids.map(async id => {
        return await prisma.user.findUnique({ where: { id } });
      }));
    `);
    // Promise.all(map) is still N queries — still worth flagging
    expect(nPlusOneQueryRule.run(ctx)).toHaveLength(1);
  });

  it('flags await inside a while loop', () => {
    const ctx = createContext(`
      while (cursor) {
        const item = await prisma.order.findFirst({ where: { id: cursor } });
        cursor = item?.nextId;
      }
    `);
    expect(nPlusOneQueryRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag await db call outside any loop', () => {
    const ctx = createContext(`
      const users = await prisma.user.findMany({ where: { active: true } });
    `);
    expect(nPlusOneQueryRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag non-db awaits in a loop', () => {
    const ctx = createContext(`
      for (const item of items) {
        await sendEmail(item.email);
      }
    `);
    expect(nPlusOneQueryRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag await outside the loop body', () => {
    const ctx = createContext(`
      const invitations = await prisma.businessInvitation.findMany({
        where: { businessId: id }
      });
      for (const inv of invitations) {
        console.log(inv.email);
      }
    `);
    expect(nPlusOneQueryRule.run(ctx)).toHaveLength(0);
  });
});
