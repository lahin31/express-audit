import { describe, it, expect } from 'vitest';
import { AuditEngine } from '../src/core/engine.js';
import { jwtHardcodedRule } from '../src/rules/authentication/jwt-hardcoded.js';
import { allRules } from '../src/rules/index.js';
import { resolve } from 'path';

describe('AuditEngine', () => {
  it('registers rules and returns audit result', async () => {
    const engine = new AuditEngine();
    engine.registerRule(jwtHardcodedRule);

    const examplesDir = resolve('examples/vulnerable-app');
    const result = await engine.audit(examplesDir);

    expect(result).toBeDefined();
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.findings).toBeDefined();
    expect(Array.isArray(result.findings)).toBe(true);
    expect(result.version).toBe('1.0.0');
  });

  it('respects disabled rules in config', async () => {
    const engine = new AuditEngine({
      rules: { disabled: ['JWT001'] },
    });
    engine.registerRule(jwtHardcodedRule);

    const result = await engine.audit(resolve('examples/vulnerable-app'));
    expect(result.findings.filter(f => f.ruleId === 'JWT001')).toHaveLength(0);
  });

  it('runs full audit on vulnerable-app and finds multiple issues', async () => {
    const engine = new AuditEngine();
    engine.registerRules(allRules);

    const result = await engine.audit(resolve('examples/vulnerable-app'));

    // Should find JWT001 (hardcoded secret)
    expect(result.findings.some(f => f.ruleId === 'JWT001')).toBe(true);
    // Should find SESSION001 (hardcoded session secret)
    expect(result.findings.some(f => f.ruleId === 'SESSION001')).toBe(true);
    // Should find CORS001 (wildcard origin)
    expect(result.findings.some(f => f.ruleId === 'CORS001')).toBe(true);

    // Score should be below 100 due to findings
    expect(result.score).toBeLessThan(100);

    // Category scores should exist
    expect(result.categoryScores.length).toBeGreaterThan(0);
  });

  it('produces a higher score on the secure-app', async () => {
    const vulnerable = new AuditEngine();
    vulnerable.registerRules(allRules);
    const vulnResult = await vulnerable.audit(resolve('examples/vulnerable-app'));

    const secure = new AuditEngine();
    secure.registerRules(allRules);
    const secureResult = await secure.audit(resolve('examples/secure-app'));

    expect(secureResult.score).toBeGreaterThan(vulnResult.score);
  });

  it('returns CASA note when CASA rules are present', async () => {
    const engine = new AuditEngine();
    engine.registerRules(allRules);
    const result = await engine.audit(resolve('examples/vulnerable-app'));
    expect(result.casaNote).toBeDefined();
    expect(result.casaNote).toContain('Google CASA');
  });
});
