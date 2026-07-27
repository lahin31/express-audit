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
 * Detect missing state parameter validation in OAuth callbacks
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
    const findings: Finding[] = [];

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        // Look for route handlers named "callback" that don't check state
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
            // Check if the handler function checks for state
            const handler = path.node.arguments[path.node.arguments.length - 1];
            if (
              handler &&
              (handler.type === 'ArrowFunctionExpression' || handler.type === 'FunctionExpression')
            ) {
              const handlerSource = context.source.slice(
                handler.start || 0,
                handler.end || 0
              );

              if (
                !handlerSource.includes('state') &&
                !handlerSource.includes('passport.authenticate')
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
      '*',
    ];

    traverse(ast, {
      StringLiteral(path: NodePath<BabelTypes.StringLiteral>) {
        const value = path.node.value;
        if (broadScopes.some(scope => value.includes(scope))) {
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
