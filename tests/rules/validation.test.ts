import { describe, it, expect } from 'vitest';
import { prototypePollutionMergeRule } from '../../src/rules/validation/prototype-pollution.js';
import { createContext } from '../helpers.js';

// ---------------------------------------------------------------------------
// PP001 – Object.assign with user input
// ---------------------------------------------------------------------------
describe('PP001 – Object.assign with user input', () => {
  it('flags Object.assign(target, req.body)', () => {
    const ctx = createContext(`
      app.post('/update', (req, res) => {
        Object.assign(config, req.body);
      });
    `);
    const findings = prototypePollutionMergeRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('PP001');
    expect(findings[0].severity).toBe('high');
  });

  it('flags Object.assign with req.query', () => {
    const ctx = createContext(`Object.assign(defaults, req.query);`);
    expect(prototypePollutionMergeRule.run(ctx)).toHaveLength(1);
  });

  it('flags Object.assign with req.params', () => {
    const ctx = createContext(`Object.assign(options, req.params);`);
    expect(prototypePollutionMergeRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag Object.assign with no user input', () => {
    const ctx = createContext(`Object.assign(target, { safe: true });`);
    expect(prototypePollutionMergeRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag Object.assign with only one argument', () => {
    const ctx = createContext(`Object.assign(target);`);
    expect(prototypePollutionMergeRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag Object.keys or Object.values', () => {
    const ctx = createContext(`Object.keys(req.body);`);
    expect(prototypePollutionMergeRule.run(ctx)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// PP001 – lodash / merge functions with user input
// ---------------------------------------------------------------------------
describe('PP001 – lodash merge with user input', () => {
  it('flags _.merge(target, req.body)', () => {
    const ctx = createContext(`_.merge(config, req.body);`);
    const findings = prototypePollutionMergeRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('PP001');
  });

  it('flags lodash.merge(target, req.body)', () => {
    const ctx = createContext(`lodash.merge(defaults, req.body);`);
    expect(prototypePollutionMergeRule.run(ctx)).toHaveLength(1);
  });

  it('flags bare merge(target, req.body)', () => {
    const ctx = createContext(`merge(config, req.body);`);
    expect(prototypePollutionMergeRule.run(ctx)).toHaveLength(1);
  });

  it('flags deepMerge(target, req.body)', () => {
    const ctx = createContext(`deepMerge(defaults, req.body);`);
    expect(prototypePollutionMergeRule.run(ctx)).toHaveLength(1);
  });

  it('flags extend(target, req.body)', () => {
    const ctx = createContext(`extend(options, req.query);`);
    expect(prototypePollutionMergeRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag _.merge with no user input', () => {
    const ctx = createContext(`_.merge(defaults, { timeout: 5000 });`);
    expect(prototypePollutionMergeRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag _.merge with a single safe argument', () => {
    const ctx = createContext(`_.merge(a, b);`);
    expect(prototypePollutionMergeRule.run(ctx)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// PP001 – Computed property assignment with user-controlled key
// ---------------------------------------------------------------------------
describe('PP001 – Computed property assignment', () => {
  it('flags obj[req.body.key] = value', () => {
    const ctx = createContext(`
      app.post('/set', (req, res) => {
        config[req.body.key] = req.body.value;
      });
    `);
    const findings = prototypePollutionMergeRule.run(ctx);
    expect(findings.some(f => f.ruleId === 'PP001')).toBe(true);
  });

  it('flags obj[req.query.field] = value', () => {
    const ctx = createContext(`settings[req.query.field] = req.query.value;`);
    expect(prototypePollutionMergeRule.run(ctx).some(f => f.ruleId === 'PP001')).toBe(true);
  });

  it('does not flag obj[staticKey] = value', () => {
    const ctx = createContext(`config['timeout'] = 5000;`);
    expect(prototypePollutionMergeRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag obj.property = value (non-computed)', () => {
    const ctx = createContext(`config.timeout = 5000;`);
    expect(prototypePollutionMergeRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag array index assignment', () => {
    const ctx = createContext(`arr[0] = 'value';`);
    expect(prototypePollutionMergeRule.run(ctx)).toHaveLength(0);
  });
});
