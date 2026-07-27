import { describe, it, expect } from 'vitest';
import { jwtHardcodedRule } from '../../src/rules/authentication/jwt-hardcoded.js';
import { jwtNoExpiryRule } from '../../src/rules/authentication/jwt-no-expiry.js';
import { weakBcryptRule } from '../../src/rules/authentication/weak-bcrypt.js';
import { plaintextPasswordRule } from '../../src/rules/authentication/plaintext-password.js';
import { createContext } from '../helpers.js';

// ---------------------------------------------------------------------------
// JWT001 – Hardcoded JWT secret
// ---------------------------------------------------------------------------
describe('JWT001 – Hardcoded JWT secret', () => {
  it('flags jwt.sign() with a string literal secret', () => {
    const ctx = createContext(
      "const jwt = require('jsonwebtoken');\n" +
      "const token = jwt.sign({ userId: 1 }, 'super-secret');",
    );
    const findings = jwtHardcodedRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('JWT001');
    expect(findings[0].severity).toBe('critical');
  });

  it('does not flag jwt.sign() with process.env secret', () => {
    const ctx = createContext(`
      const jwt = require('jsonwebtoken');
      const token = jwt.sign({ userId: 1 }, process.env.JWT_SECRET);
    `);
    expect(jwtHardcodedRule.run(ctx)).toHaveLength(0);
  });

  it('flags jwt.verify() with a string literal secret', () => {
    const ctx = createContext(`
      const jwt = require('jsonwebtoken');
      jwt.verify(token, 'hardcoded-key');
    `);
    const findings = jwtHardcodedRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('JWT001');
  });

  it('does not flag unrelated method calls', () => {
    const ctx = createContext(`
      const obj = { sign: (a, b) => {} };
      obj.sign('data', 'secret');
    `);
    expect(jwtHardcodedRule.run(ctx)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// JWT002 – Missing expiration
// ---------------------------------------------------------------------------
describe('JWT002 – Missing JWT expiration', () => {
  it('flags jwt.sign() with no options argument', () => {
    const ctx = createContext(`
      const jwt = require('jsonwebtoken');
      jwt.sign({ userId: 1 }, process.env.JWT_SECRET);
    `);
    const findings = jwtNoExpiryRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('JWT002');
  });

  it('flags jwt.sign() with options object missing expiresIn', () => {
    const ctx = createContext(`
      const jwt = require('jsonwebtoken');
      jwt.sign({ userId: 1 }, process.env.JWT_SECRET, { algorithm: 'HS256' });
    `);
    const findings = jwtNoExpiryRule.run(ctx);
    expect(findings).toHaveLength(1);
  });

  it('does not flag jwt.sign() with expiresIn set', () => {
    const ctx = createContext(`
      const jwt = require('jsonwebtoken');
      jwt.sign({ userId: 1 }, process.env.JWT_SECRET, { expiresIn: '15m' });
    `);
    expect(jwtNoExpiryRule.run(ctx)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// AUTH001 – Weak bcrypt cost
// ---------------------------------------------------------------------------
describe('AUTH001 – Weak bcrypt cost factor', () => {
  it('flags bcrypt.hash() with cost < 12', () => {
    const ctx = createContext(`
      const bcrypt = require('bcrypt');
      bcrypt.hash(password, 8);
    `);
    const findings = weakBcryptRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('AUTH001');
    expect(findings[0].severity).toBe('high');
  });

  it('flags cost = 1 (minimum insecure)', () => {
    const ctx = createContext(`bcrypt.hash(pwd, 1);`);
    expect(weakBcryptRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag bcrypt.hash() with cost >= 12', () => {
    const ctx = createContext(`bcrypt.hash(password, 12);`);
    expect(weakBcryptRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag bcrypt.hash() with cost = 14', () => {
    const ctx = createContext(`bcrypt.hash(password, 14);`);
    expect(weakBcryptRule.run(ctx)).toHaveLength(0);
  });

  it('flags bcryptjs with low cost', () => {
    const ctx = createContext(`bcryptjs.hash(password, 5);`);
    expect(weakBcryptRule.run(ctx)).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// AUTH002 – Plaintext password comparison
// ---------------------------------------------------------------------------
describe('AUTH002 – Plaintext password comparison', () => {
  it('flags direct === comparison on .password', () => {
    const ctx = createContext(`
      if (user.password === req.body.password) { login(); }
    `);
    const findings = plaintextPasswordRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('AUTH002');
    expect(findings[0].severity).toBe('critical');
  });

  it('flags != comparison on .password', () => {
    const ctx = createContext(`
      if (user.password != inputPassword) { throw new Error(); }
    `);
    expect(plaintextPasswordRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag bcrypt.compare calls', () => {
    const ctx = createContext(`
      const valid = await bcrypt.compare(input, user.passwordHash);
    `);
    expect(plaintextPasswordRule.run(ctx)).toHaveLength(0);
  });
});
