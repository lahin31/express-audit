import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getObjectProperty, getStringValue, getNodeLine, findImports } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

const CASA_REFERENCES = [
  {
    title: 'Google CASA Requirements',
    url: 'https://appdefensealliance.dev/casa',
  },
  {
    title: 'OWASP ASVS v4.0 – Application Security Verification Standard',
    url: 'https://owasp.org/www-project-application-security-verification-standard/',
  },
  {
    title: 'RFC 6749 – The OAuth 2.0 Authorization Framework',
    url: 'https://www.rfc-editor.org/rfc/rfc6749',
  },
  {
    title: 'RFC 7636 – Proof Key for Code Exchange (PKCE)',
    url: 'https://www.rfc-editor.org/rfc/rfc7636',
  },
  {
    title: 'RFC 7009 – OAuth 2.0 Token Revocation',
    url: 'https://www.rfc-editor.org/rfc/rfc7009',
  },
  {
    title: 'OpenID Connect Core 1.0',
    url: 'https://openid.net/specs/openid-connect-core-1_0.html',
  },
];

/**
 * CASA001 - Refresh tokens stored insecurely
 */
export const casaRefreshTokenStorageRule: Rule = {
  id: 'CASA001',
  severity: 'critical',
  category: 'CASA Readiness',
  title: 'Refresh Token Stored Insecurely',
  description: 'OAuth refresh tokens appear to be stored without encryption or in a potentially insecure location',
  detectorType: 'ast',
  remediation: 'Encrypt refresh tokens before storage. Use a KMS or envelope encryption. Store in a secure, access-controlled database with audit logging.',
  references: CASA_REFERENCES,

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const ast = context.ast as File;
    const findings: Finding[] = [];

    traverse(ast, {
      AssignmentExpression(path: NodePath<BabelTypes.AssignmentExpression>) {
        const { left, right } = path.node;

        // Look for refresh_token = something (without encryption)
        const isRefreshToken = (node: BabelTypes.Node): boolean => {
          if (node.type === 'MemberExpression') {
            const prop = node.property;
            if (prop.type === 'Identifier') {
              return prop.name === 'refresh_token' || prop.name === 'refreshToken';
            }
          }
          if (node.type === 'Identifier') {
            return node.name === 'refresh_token' || node.name === 'refreshToken';
          }
          return false;
        };

        if (isRefreshToken(left)) {
          // Check if the right side involves encryption
          const rightSource = context.source.slice(right.start || 0, right.end || 0);
          const hasEncryption =
            rightSource.includes('encrypt') ||
            rightSource.includes('cipher') ||
            rightSource.includes('crypto.') ||
            rightSource.includes('aes') ||
            rightSource.includes('kms') ||
            rightSource.includes('KMS');

          if (!hasEncryption) {
            findings.push({
              ruleId: 'CASA001',
              severity: 'critical',
              category: 'CASA Readiness',
              title: 'Refresh Token May Be Stored Unencrypted',
              description: 'Refresh token assignment detected without visible encryption',
              impact: 'Unencrypted refresh tokens in databases or storage can be stolen and used to impersonate users indefinitely.',
              remediation: 'Encrypt refresh tokens using AES-256 or use a key management service before storage.',
              references: CASA_REFERENCES,
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
 * CASA002 - Missing OAuth token revocation
 *
 * This is a PROJECT-LEVEL check. It fires at most once, from the application
 * entry file, only when the project actually uses an OAuth library.
 * It scans all project files for revocation patterns before reporting.
 */
export const casaTokenRevocationRule: Rule = {
  id: 'CASA002',
  severity: 'high',
  category: 'CASA Readiness',
  title: 'Missing OAuth Token Revocation',
  description: 'No OAuth token revocation endpoint or mechanism detected in the project',
  detectorType: 'file',
  remediation: 'Implement token revocation per RFC 7009. Provide an endpoint that invalidates tokens and removes them from storage.',
  references: [
    {
      title: 'RFC 7009 – OAuth 2.0 Token Revocation',
      url: 'https://www.rfc-editor.org/rfc/rfc7009',
    },
    ...CASA_REFERENCES,
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    // Only trigger once per project — from the entry file
    const { filePath, projectRoot, allFiles } = context;
    const rel = filePath.replace(/\\/g, '/').replace(projectRoot.replace(/\\/g, '/'), '').replace(/^\//, '');
    const depth = rel.split('/').length;
    const basename = rel.split('/').pop() ?? '';
    const entryNames = ['app.ts', 'app.js', 'server.ts', 'server.js', 'main.ts', 'main.js', 'index.ts', 'index.js'];
    const isEntry = entryNames.includes(basename) && depth <= 2 && (
      context.source.includes('express()') ||
      context.source.includes('app.listen') ||
      context.source.includes('app.use(')
    );
    if (!isEntry) return [];

    // Require the project to actually use OAuth — check all files for OAuth imports
    const OAUTH_PACKAGES = [
      "'passport'", '"passport"',
      "'openid-client'", '"openid-client"',
      "'passport-google-oauth'", '"passport-google-oauth"',
      "'passport-oauth2'", '"passport-oauth2"',
      "'passport-github'", '"passport-github"',
    ];

    const OAUTH_PATTERNS = [
      'authorizationURL', 'callbackURL',
      'access_token', 'refresh_token',
      'authorization_code', 'id_token',
      'oauth2', 'OAuth2',
    ];

    // Read all project source files to determine if OAuth is used at all,
    // and whether any file implements revocation.
    let projectUsesOAuth = false;
    let projectHasRevocation = false;

    for (const file of allFiles) {
      if (!existsSync(file)) continue;
      let src: string;
      try { src = readFileSync(file, 'utf-8'); } catch { continue; }

      if (!projectUsesOAuth) {
        projectUsesOAuth =
          OAUTH_PACKAGES.some(p => src.includes(p)) ||
          OAUTH_PATTERNS.some(p => src.includes(p));
      }

      if (!projectHasRevocation) {
        projectHasRevocation =
          src.includes('revoke') ||
          src.includes('revokeToken') ||
          src.includes('token_revocation') ||
          src.includes('/logout') ||
          src.includes('/signout');
      }

      if (projectUsesOAuth && projectHasRevocation) break;
    }

    // Only report if the project actually uses OAuth but has no revocation
    if (!projectUsesOAuth || projectHasRevocation) return [];

    return [{
      ruleId: 'CASA002',
      severity: 'high',
      category: 'CASA Readiness',
      title: 'Missing OAuth Token Revocation',
      description: 'Project uses OAuth but no token revocation endpoint or mechanism was found',
      impact: 'Without revocation, compromised tokens remain valid until expiration, allowing extended unauthorized access.',
      remediation: 'Implement a /auth/revoke endpoint following RFC 7009',
      references: casaTokenRevocationRule.references,
      filePath,
    }];
  },
};

/**
 * CASA003 - OAuth credentials logged
 */
export const casaOauthCredentialsLoggedRule: Rule = {
  id: 'CASA003',
  severity: 'critical',
  category: 'CASA Readiness',
  title: 'OAuth Credentials in Logs',
  description: 'OAuth access tokens, refresh tokens, or client secrets may be written to logs',
  detectorType: 'ast',
  remediation: 'Never log OAuth credentials. Sanitize all token-related values before logging.',
  references: CASA_REFERENCES,

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const ast = context.ast as File;
    const findings: Finding[] = [];

    const sensitiveOauthProps = [
      'access_token', 'accessToken',
      'refresh_token', 'refreshToken',
      'client_secret', 'clientSecret',
      'id_token', 'idToken',
    ];

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        // Detect logging calls
        const isLog =
          callee.type === 'MemberExpression' &&
          callee.object.type === 'Identifier' &&
          (callee.object.name === 'console' || callee.object.name === 'logger') &&
          callee.property.type === 'Identifier';

        if (!isLog) return;

        for (const arg of path.node.arguments) {
          const argSource = context.source.slice(arg.start || 0, arg.end || 0);
          const found = sensitiveOauthProps.find(prop => argSource.includes(prop));
          if (found) {
            findings.push({
              ruleId: 'CASA003',
              severity: 'critical',
              category: 'CASA Readiness',
              title: 'OAuth Credentials May Be Logged',
              description: `OAuth credential property "${found}" may be written to logs`,
              impact: 'Logged OAuth tokens can be stolen from log files, aggregation systems, or monitoring dashboards.',
              remediation: `Remove ${found} from log statements`,
              references: CASA_REFERENCES,
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
 * CASA004 - Missing audit logging for OAuth events
 */
export const casaAuditLoggingRule: Rule = {
  id: 'CASA004',
  severity: 'medium',
  category: 'CASA Readiness',
  title: 'Missing Audit Logging for OAuth Events',
  description: 'No audit logging detected for OAuth authorization events',
  detectorType: 'file',
  remediation: 'Log authentication and authorization events including: login, logout, token issue, token revocation, and permission changes.',
  references: [
    {
      title: 'OWASP Logging Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
    },
    ...CASA_REFERENCES,
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const { source, filePath } = context;

    // Only check files that use a recognised OAuth library.
    // Patterns alone (access_token, refresh_token) are too broad — they appear
    // in AppSumo integrations, payment flows, and other non-OAuth code.
    // Requiring an actual OAuth library import keeps false positives low.
    const OAUTH_LIBS = [
      "'passport'", '"passport"',
      "'openid-client'", '"openid-client"',
      "'passport-google-oauth'", '"passport-google-oauth"',
      "'passport-oauth2'", '"passport-oauth2"',
      "'passport-github2'", '"passport-github2"',
      "'passport-facebook'", '"passport-facebook"',
      "'simple-oauth2'", '"simple-oauth2"',
    ];

    const hasOAuthImport = OAUTH_LIBS.some(lib => source.includes(lib));

    // Also match files with strong OAuth flow indicators (not just generic token strings)
    const hasStrongOAuthPattern =
      source.includes('authorizationURL') ||
      source.includes('callbackURL') ||
      source.includes('authorization_code') ||
      (source.includes('id_token') && source.includes('nonce'));

    if (!hasOAuthImport && !hasStrongOAuthPattern) return [];

    const hasAuditLog =
      source.includes('audit') ||
      source.includes('auditLog') ||
      source.includes('audit_log') ||
      (source.includes('logger') &&
        (source.includes('login') || source.includes('oauth') || source.includes('token')));

    if (!hasAuditLog) {
      return [{
        ruleId: 'CASA004',
        severity: 'medium',
        category: 'CASA Readiness',
        title: 'Missing OAuth Audit Logging',
        description: 'No audit logging detected for OAuth/authentication events',
        impact: 'Without audit logs, security incidents are difficult to detect, investigate, and respond to.',
        remediation: 'Add structured audit logging for: token issuance, login events, logout, token revocation, and auth failures.',
        references: casaAuditLoggingRule.references,
        filePath: context.filePath,
      }];
    }

    return [];
  },
};

/**
 * CASA005 - Missing nonce validation
 */
export const casaNonceRule: Rule = {
  id: 'CASA005',
  severity: 'high',
  category: 'CASA Readiness',
  title: 'Missing Nonce Validation',
  description: 'OpenID Connect flows may be missing nonce validation',
  detectorType: 'ast',
  remediation: 'Include a nonce in the authorization request and validate it in the ID token to prevent replay attacks.',
  references: [
    {
      title: 'OpenID Connect Core 1.0 – Nonce Implementation Notes',
      url: 'https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes',
    },
    {
      title: 'OAuth 2.0 Security Best Current Practice – Replay Prevention',
      url: 'https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics',
    },
    ...CASA_REFERENCES,
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const ast = context.ast as File;

    // Require an OIDC library import — don't trigger on path name alone
    const hasOIDC = findImports(ast, 'openid-client') || findImports(ast, 'passport-openidconnect');
    if (!hasOIDC) return [];

    const { source } = context;
    const hasNonce = source.includes('nonce');

    if (!hasNonce) {
      return [{
        ruleId: 'CASA005',
        severity: 'high',
        category: 'CASA Readiness',
        title: 'Missing Nonce Validation',
        description: 'OpenID Connect usage detected without nonce validation',
        impact: 'Without nonce validation, ID tokens can be replayed by attackers.',
        remediation: 'Generate and store a nonce per request, then validate it in the token response.',
        references: casaNonceRule.references,
        filePath: context.filePath,
      }];
    }

    return [];
  },
};
