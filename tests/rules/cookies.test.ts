import { describe, it, expect } from 'vitest';
import { cookieSecurityRule } from '../../src/rules/cookies/cookie-security.js';
import { sessionSecurityRule } from '../../src/rules/cookies/session-security.js';
import { createContext } from '../helpers.js';

// ---------------------------------------------------------------------------
// COOKIE001 – Insecure cookie flags
// ---------------------------------------------------------------------------
describe('COOKIE001 – Insecure cookie configuration', () => {
  it('flags res.cookie() with no options', () => {
    const ctx = createContext(`res.cookie('token', value);`);
    const findings = cookieSecurityRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('COOKIE001');
  });

  it('flags missing httpOnly', () => {
    const ctx = createContext(`res.cookie('token', value, { secure: true, sameSite: 'strict' });`);
    const findings = cookieSecurityRule.run(ctx);
    expect(findings.some(f => f.title.includes('httpOnly'))).toBe(true);
  });

  it('flags missing secure flag', () => {
    const ctx = createContext(`res.cookie('token', value, { httpOnly: true, sameSite: 'strict' });`);
    const findings = cookieSecurityRule.run(ctx);
    expect(findings.some(f => f.title.includes('Secure'))).toBe(true);
  });

  it('flags httpOnly: false explicitly', () => {
    const ctx = createContext(`res.cookie('a', v, { httpOnly: false, secure: true, sameSite: 'strict' });`);
    const findings = cookieSecurityRule.run(ctx);
    expect(findings.some(f => f.title.includes('httpOnly'))).toBe(true);
  });

  it('does not flag fully secured cookie', () => {
    const ctx = createContext(`
      res.cookie('token', value, { httpOnly: true, secure: true, sameSite: 'strict' });
    `);
    expect(cookieSecurityRule.run(ctx)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// SESSION001 – Insecure session configuration
// ---------------------------------------------------------------------------
describe('SESSION001 – Insecure session configuration', () => {
  it('flags hardcoded session secret', () => {
    const ctx = createContext(`
      session({ secret: 'hardcoded-secret', saveUninitialized: false, resave: false });
    `);
    const findings = sessionSecurityRule.run(ctx);
    expect(findings.some(f => f.title.toLowerCase().includes('hardcoded'))).toBe(true);
    expect(findings.some(f => f.severity === 'critical')).toBe(true);
  });

  it('flags saveUninitialized: true', () => {
    const ctx = createContext(`
      session({ secret: process.env.SECRET, saveUninitialized: true, resave: false });
    `);
    const findings = sessionSecurityRule.run(ctx);
    expect(findings.some(f => f.title.includes('saveUninitialized'))).toBe(true);
  });

  it('flags missing secret', () => {
    const ctx = createContext(`session({ saveUninitialized: false, resave: false });`);
    const findings = sessionSecurityRule.run(ctx);
    expect(findings.some(f => f.title.includes('Secret'))).toBe(true);
  });

  it('does not flag a well-configured session', () => {
    const ctx = createContext(`
      session({
        secret: process.env.SESSION_SECRET,
        saveUninitialized: false,
        resave: false,
        cookie: { httpOnly: true, secure: true, sameSite: 'strict' },
      });
    `);
    const findings = sessionSecurityRule.run(ctx);
    // Should produce no critical/high findings
    const bad = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    expect(bad).toHaveLength(0);
  });
});
