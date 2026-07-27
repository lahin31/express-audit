import { describe, it, expect } from 'vitest';
import { hardcodedSecretsRule } from '../../src/rules/secrets/hardcoded-secrets.js';
import { createContext } from '../helpers.js';

describe('SECRET001-010 – Hardcoded secrets', () => {
  it('flags AWS access key pattern', () => {
    const ctx = createContext(
      `const key = "AKIAIOSFODNN7EXAMPLE";`,
      'config.ts',
    );
    const findings = hardcodedSecretsRule.run(ctx);
    expect(findings.some(f => f.title.includes('AWS Access Key'))).toBe(true);
  });

  it('flags Google API key', () => {
    const ctx = createContext(
      `const apiKey = "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI";`,
      'config.ts',
    );
    const findings = hardcodedSecretsRule.run(ctx);
    expect(findings.some(f => f.title.includes('Google API Key'))).toBe(true);
  });

  it('flags Stripe secret key', () => {
    const ctx = createContext(
      `const stripe = require('stripe')('sk_live_4eC39HqLyjWDarjtT1zdp7dc');`,
      'payment.ts',
    );
    const findings = hardcodedSecretsRule.run(ctx);
    expect(findings.some(f => f.title.includes('Stripe Secret Key'))).toBe(true);
  });

  it('flags GitHub token', () => {
    const ctx = createContext(
      `const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";`,
      'github.ts',
    );
    const findings = hardcodedSecretsRule.run(ctx);
    expect(findings.some(f => f.title.includes('GitHub Token'))).toBe(true);
  });

  it('flags PEM private key header', () => {
    const ctx = createContext(
      `const key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpA...";`,
      'keys.ts',
    );
    expect(hardcodedSecretsRule.run(ctx).length).toBeGreaterThan(0);
  });

  it('does not flag process.env references', () => {
    const ctx = createContext(
      `const key = process.env.STRIPE_KEY;`,
      'config.ts',
    );
    expect(hardcodedSecretsRule.run(ctx)).toHaveLength(0);
  });

  it('skips .env files', () => {
    const ctx = createContext(
      `STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc`,
      '.env',
    );
    expect(hardcodedSecretsRule.run(ctx)).toHaveLength(0);
  });

  it('skips test fixture files', () => {
    const ctx = createContext(
      `const key = "AKIAIOSFODNN7EXAMPLE";`,
      'auth.fixture.ts',
    );
    expect(hardcodedSecretsRule.run(ctx)).toHaveLength(0);
  });
});
