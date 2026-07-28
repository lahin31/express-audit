import { describe, it, expect } from 'vitest';
import { sensitiveLoggingRule, stackTraceExposureRule } from '../../src/rules/logging/sensitive-logging.js';
import { sensitiveResponseRule } from '../../src/rules/logging/sensitive-response.js';
import { createContext } from '../helpers.js';

describe('LOG001 – Sensitive data in logs', () => {
  it('flags console.log(user.password)', () => {
    const ctx = createContext(`console.log('User:', user.password);`);
    const findings = sensitiveLoggingRule.run(ctx);
    expect(findings.some(f => f.ruleId === 'LOG001')).toBe(true);
  });

  it('flags console.log(req.body.token)', () => {
    const ctx = createContext(`console.log(req.body.token);`);
    expect(sensitiveLoggingRule.run(ctx).some(f => f.ruleId === 'LOG001')).toBe(true);
  });

  it('flags console.log(req.body) as LOG002', () => {
    const ctx = createContext(`console.log('Request body:', req.body);`);
    const findings = sensitiveLoggingRule.run(ctx);
    expect(findings.some(f => f.ruleId === 'LOG002')).toBe(true);
  });

  it('flags logger.info with password field', () => {
    const ctx = createContext(`logger.info('password reset', user.password);`);
    expect(sensitiveLoggingRule.run(ctx).some(f => f.ruleId === 'LOG001')).toBe(true);
  });

  it('does not flag safe log statements', () => {
    const ctx = createContext(`console.log('User logged in:', user.email);`);
    expect(sensitiveLoggingRule.run(ctx)).toHaveLength(0);
  });
});

describe('LOG003 – Stack trace exposed to client', () => {
  it('flags res.json({ stack: err.stack })', () => {
    const ctx = createContext(`res.json({ message: err.message, stack: err.stack });`);
    const findings = stackTraceExposureRule.run(ctx);
    expect(findings.some(f => f.ruleId === 'LOG003')).toBe(true);
  });

  it('flags res.json(err) with err.stack in an object', () => {
    const ctx = createContext(`res.json({ error: err.message, trace: err.stack });`);
    expect(stackTraceExposureRule.run(ctx).length).toBeGreaterThan(0);
  });

  it('does not flag res.json({ error: "Internal server error" })', () => {
    const ctx = createContext(`res.json({ error: 'Internal server error' });`);
    expect(stackTraceExposureRule.run(ctx)).toHaveLength(0);
  });
});

describe('SEC001 – Sensitive data in HTTP response', () => {
  it('flags res.json with api_key field', () => {
    const ctx = createContext(`res.json({ api_key: key, data: result });`);
    const findings = sensitiveResponseRule.run(ctx);
    expect(findings.some(f => f.ruleId === 'SEC001' && f.severity === 'high')).toBe(true);
  });

  it('flags res.json with secret field', () => {
    const ctx = createContext(`res.json({ user: name, secret: s });`);
    expect(sensitiveResponseRule.run(ctx).some(f => f.ruleId === 'SEC001')).toBe(true);
  });

  it('flags res.json with password field', () => {
    const ctx = createContext(`res.json({ id: 1, password: pwd });`);
    expect(sensitiveResponseRule.run(ctx).some(f => f.ruleId === 'SEC001')).toBe(true);
  });

  it('flags res.json with access_token at medium severity', () => {
    const ctx = createContext(`res.json({ access_token: token, expires_in: 3600 });`);
    const findings = sensitiveResponseRule.run(ctx);
    expect(findings.some(f => f.ruleId === 'SEC001' && f.severity === 'medium')).toBe(true);
  });

  it('flags res.status(200).json with api_key', () => {
    const ctx = createContext(`res.status(200).json({ api_key: k, ok: true });`);
    expect(sensitiveResponseRule.run(ctx).some(f => f.ruleId === 'SEC001')).toBe(true);
  });

  it('does not flag safe response objects', () => {
    const ctx = createContext(`res.json({ id: user.id, email: user.email, name: user.name });`);
    expect(sensitiveResponseRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag non-response calls', () => {
    const ctx = createContext(`logger.info({ api_key: 'test' });`);
    expect(sensitiveResponseRule.run(ctx)).toHaveLength(0);
  });
});
