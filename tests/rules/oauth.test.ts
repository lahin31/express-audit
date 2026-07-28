import { describe, it, expect } from 'vitest';
import { oauthStateMissingRule } from '../../src/rules/oauth/oauth-security.js';
import { createContext } from '../helpers.js';

describe('OAUTH002 – Missing OAuth state validation', () => {
  it('does not flag a custom callback route without an OAuth library import', () => {
    // Real-world: AppSumo callback that reads req.query.code directly —
    // not a standard OAuth flow, no passport/openid-client imported
    const ctx = createContext(`
      appsumo_router.get('/appsumo/auth/callback', async (req, res, next) => {
        const authorizationCode = req.query.code;
        if (authorizationCode) {
          res.status(200).send('OAuth process complete.');
        } else {
          res.status(400).send('Missing authorization code.');
        }
      });
    `);
    expect(oauthStateMissingRule.run(ctx)).toHaveLength(0);
  });

  it('flags a passport-based callback route without state validation', () => {
    const ctx = createContext(
      `const passport = require('passport');\n` +
      `router.get('/auth/google/callback', async (req, res, next) => {\n` +
      `  const code = req.query.code;\n` +
      `  res.redirect('/dashboard');\n` +
      `});\n`,
    );
    const findings = oauthStateMissingRule.run(ctx);
    expect(findings.some(f => f.ruleId === 'OAUTH002')).toBe(true);
  });

  it('does not flag a passport callback that validates state', () => {
    const ctx = createContext(
      `const passport = require('passport');\n` +
      `router.get('/auth/callback', async (req, res, next) => {\n` +
      `  if (req.query.state !== req.session.oauthState) return res.status(400).send('Invalid state');\n` +
      `  res.redirect('/dashboard');\n` +
      `});\n`,
    );
    expect(oauthStateMissingRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag a callback that uses passport.authenticate', () => {
    const ctx = createContext(
      `const passport = require('passport');\n` +
      `router.get('/auth/google/callback',\n` +
      `  passport.authenticate('google', { failureRedirect: '/login' }),\n` +
      `  (req, res) => res.redirect('/'),\n` +
      `);\n`,
    );
    expect(oauthStateMissingRule.run(ctx)).toHaveLength(0);
  });
});
