import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getObjectProperty, getStringValue, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';
import { findImports } from '../../core/ast-helpers.js';

/**
 * Detects missing PKCE in OAuth flows
 */
export const oauthPkceRule: Rule = {
  id: 'OAUTH001',
  severity: 'high',
  category: 'OAuth',
  title: 'Missing PKCE in OAuth Flow',
  description: 'OAuth authorization code flow does not use PKCE (Proof Key for Code Exchange)',
  detectorType: 'ast',
  remediation: 'Implement PKCE by generating a code_verifier and code_challenge for each authorization request.',
  references: [
    {
      title: 'RFC 7636 - PKCE',
      url: 'https://tools.ietf.org/html/rfc7636',
    },
    {
      title: 'OAuth 2.0 Security Best Current Practice',
      url: 'https://tools.ietf.org/html/draft-ietf-oauth-security-topics',
    },
    {
      title: 'Google OAuth PKCE Guide',
      url: 'https://developers.google.com/identity/protocols/oauth2/native-app',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const ast = context.ast as File;
    const findings: Finding[] = [];

    // Check for OAuth library imports
    const hasPassport = findImports(ast, 'passport');
    const hasOAuth2 = findImports(ast, 'simple-oauth2') || 
                      findImports(ast, 'oauth2-server') ||
                      findImports(ast, 'client-oauth2') ||
                      findImports(ast, 'openid-client');

    if (!hasPassport && !hasOAuth2) return [];

    traverse(ast, {
      ObjectExpression(path: NodePath<BabelTypes.ObjectExpression>) {
        // Check for OAuth configuration objects that lack PKCE
        const authorizationUrl = getObjectProperty(path.node, 'authorizationURL') ||
                                  getObjectProperty(path.node, 'authorizationUrl');
        const tokenUrl = getObjectProperty(path.node, 'tokenURL') ||
                         getObjectProperty(path.node, 'tokenUrl');

        if (authorizationUrl && tokenUrl) {
          // This looks like an OAuth config - check for PKCE
          const pkce = getObjectProperty(path.node, 'pkce');
          const codeChallenge = getObjectProperty(path.node, 'code_challenge');

          if (!pkce && !codeChallenge) {
            findings.push({
              ruleId: 'OAUTH001',
              severity: 'high',
              category: 'OAuth',
              title: 'Missing PKCE in OAuth Configuration',
              description: 'OAuth flow configured without PKCE protection',
              impact: 'Without PKCE, authorization codes can be intercepted and used by attackers (authorization code interception attack).',
              remediation: 'Enable PKCE: { pkce: { methods: ["S256"] } }',
              references: oauthPkceRule.references,
              filePath: context.filePath,
              line: getNodeLine(path.node),
            });
          }
        }
      },
    });

    return findings;
  },
};

/**
 * Detect missing state parameter validation in OAuth callbacks.
 * Only fires when the file actually imports an OAuth library — prevents
 * false positives on custom callback routes that happen to have "callback"
 * or "oauth" in their path but are not OAuth flows.
 */
export const oauthStateMissingRule: Rule = {
  id: 'OAUTH002',
  severity: 'high',
  category: 'OAuth',
  title: 'Missing OAuth State Validation',
  description: 'OAuth callback does not validate the state parameter, leaving it vulnerable to CSRF',
  detectorType: 'ast',
  remediation: 'Validate the state parameter in OAuth callbacks to prevent CSRF attacks.',
  references: [
    {
      title: 'OWASP - OAuth CSRF Prevention',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
    },
    {
      title: 'RFC 6749 - State Parameter',
      url: 'https://tools.ietf.org/html/rfc6749#section-10.12',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const ast = context.ast as File;

    // Gate: only check files that actually use an OAuth library.
    // A route with "callback" in the path is not an OAuth callback unless
    // the file imports passport, openid-client, or a similar library.
    const OAUTH_LIBS = [
      'passport', 'openid-client', 'client-oauth2',
      'simple-oauth2', 'oauth2-server', 'passport-oauth2',
      'passport-google-oauth2', 'passport-github2', 'passport-facebook',
    ];
    const usesOAuth = OAUTH_LIBS.some(lib => findImports(ast, lib));

    // Also accept files that directly construct OAuth URLs (authorizationURL pattern)
    const hasOAuthPattern =
      context.source.includes('authorizationURL') ||
      context.source.includes('callbackURL') ||
      context.source.includes('authorization_code');

    if (!usesOAuth && !hasOAuthPattern) return [];

    const findings: Finding[] = [];

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        if (
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          callee.property.name === 'get'
        ) {
          const routeArg = path.node.arguments[0];
          if (
            routeArg?.type === 'StringLiteral' &&
            (routeArg.value.includes('callback') || routeArg.value.includes('oauth'))
          ) {
            const handler = path.node.arguments[path.node.arguments.length - 1];
            if (
              handler &&
              (handler.type === 'ArrowFunctionExpression' || handler.type === 'FunctionExpression')
            ) {
              // Check handler body AND all arguments for state/passport signals
              const allArgsSource = context.source.slice(
                path.node.arguments[1]?.start ?? 0,
                path.node.end ?? 0,
              );

              if (
                !allArgsSource.includes('state') &&
                !allArgsSource.includes('passport.authenticate')
              ) {
                findings.push({
                  ruleId: 'OAUTH002',
                  severity: 'high',
                  category: 'OAuth',
                  title: 'Missing OAuth State Validation',
                  description: `OAuth callback route "${routeArg.value}" does not validate state parameter`,
                  impact: 'Without state validation, attackers can perform CSRF attacks to link victim accounts to attacker-controlled OAuth sessions.',
                  remediation: 'Validate state: if (req.query.state !== req.session.oauthState) { return res.status(400).send("Invalid state"); }',
                  references: oauthStateMissingRule.references,
                  filePath: context.filePath,
                  line: getNodeLine(path.node),
                });
              }
            }
          }
        }
      },
    });

    return findings;
  },
};

/**
 * Detect broad OAuth scopes
 */
export const oauthBroadScopesRule: Rule = {
  id: 'OAUTH003',
  severity: 'medium',
  category: 'OAuth',
  title: 'Overly Broad OAuth Scopes',
  description: 'OAuth scopes requested are broader than necessary',
  detectorType: 'ast',
  remediation: 'Follow the principle of least privilege: request only the minimum scopes needed.',
  references: [
    {
      title: 'Google OAuth Scopes Best Practices',
      url: 'https://developers.google.com/identity/protocols/oauth2/scopes',
    },
    {
      title: 'OWASP - OAuth Security',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const ast = context.ast as File;
    const findings: Finding[] = [];

    const broadScopes = [
      'https://www.googleapis.com/auth/cloud-platform',
      'https://mail.google.com/',
      'https://www.googleapis.com/auth/drive',
      'https://www.googleapis.com/auth/admin',
      'https://www.googleapis.com/auth/gmail',
      'read_write',
      'full_access',
    ];

    // These must match the FULL string value, not be a substring
    const exactBroadScopes = ['*'];

    traverse(ast, {
      StringLiteral(path: NodePath<BabelTypes.StringLiteral>) {
        const value = path.node.value;

        // Substring match for URL-style scopes
        const isSubstringMatch = broadScopes.some(scope => value.includes(scope));
        // Exact match only for wildcard — avoids matching SQL or glob patterns
        const isExactMatch = exactBroadScopes.includes(value.trim());

        if (isSubstringMatch || isExactMatch) {
          findings.push({
            ruleId: 'OAUTH003',
            severity: 'medium',
            category: 'OAuth',
            title: 'Overly Broad OAuth Scope',
            description: `Broad OAuth scope detected: ${value}`,
            impact: 'Over-privileged OAuth tokens grant attackers more access if tokens are compromised.',
            remediation: 'Request only the minimum required scopes. Review https://developers.google.com/identity/protocols/oauth2/scopes',
            references: oauthBroadScopesRule.references,
            filePath: context.filePath,
            line: getNodeLine(path.node),
          });
        }
      },
    });

    return findings;
  },
};
