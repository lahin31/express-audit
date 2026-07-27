import { describe, it, expect } from 'vitest';
import { corsWildcardRule } from '../../src/rules/cors/cors-wildcard.js';
import { createContext } from '../helpers.js';

describe('CORS001 – Wildcard origin', () => {
  it('flags cors() with no arguments', () => {
    const ctx = createContext(`
      const cors = require('cors');
      app.use(cors());
    `);
    const findings = corsWildcardRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('CORS001');
    expect(findings[0].severity).toBe('high');
  });

  it('flags cors({ origin: "*" })', () => {
    const ctx = createContext(`cors({ origin: "*" })`);
    const findings = corsWildcardRule.run(ctx);
    expect(findings.some(f => f.ruleId === 'CORS001')).toBe(true);
  });

  it('flags cors({ origin: "*", credentials: true }) as critical', () => {
    const ctx = createContext(`cors({ origin: "*", credentials: true })`);
    const findings = corsWildcardRule.run(ctx);
    const critical = findings.find(f => f.severity === 'critical');
    expect(critical).toBeDefined();
  });

  it('does not flag cors() with specific origin', () => {
    const ctx = createContext(`cors({ origin: "https://example.com" })`);
    const findings = corsWildcardRule.run(ctx);
    // origin is a string literal but not "*", dynamic function warning may appear
    const criticalOrHigh = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    expect(criticalOrHigh).toHaveLength(0);
  });

  it('does not flag cors({ origin: ["https://a.com"] })', () => {
    const ctx = createContext(`cors({ origin: ["https://a.com"] })`);
    const findings = corsWildcardRule.run(ctx);
    const bad = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    expect(bad).toHaveLength(0);
  });
});
