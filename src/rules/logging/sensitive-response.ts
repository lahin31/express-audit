import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getNodeLine } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';

/**
 * Property names that should never appear in HTTP response bodies.
 * access_token / token in a response is acceptable in some flows (e.g. OAuth token endpoint),
 * but these others should never be sent to clients.
 */
const SENSITIVE_RESPONSE_PROPS = [
  'api_key', 'apiKey', 'apikey',
  'secret', 'client_secret', 'clientSecret',
  'private_key', 'privateKey',
  'password', 'passwd', 'pwd',
  'access_key', 'accessKey',
  'aws_secret', 'awsSecret',
  'stripe_key', 'stripeKey',
];

/**
 * Token-related property names that require stricter scrutiny in responses —
 * they should only appear in dedicated auth endpoints, not general routes.
 */
const TOKEN_RESPONSE_PROPS = [
  'access_token', 'accessToken',
  'refresh_token', 'refreshToken',
  'id_token', 'idToken',
];

export const sensitiveResponseRule: Rule = {
  id: 'SEC001',
  severity: 'high',
  category: 'Logging',
  title: 'Sensitive Data in HTTP Response',
  description: 'Response body contains sensitive property names (API keys, secrets, passwords, or private keys)',
  detectorType: 'ast',
  remediation: 'Never send secrets, API keys, or private keys in HTTP responses. For tokens, use short-lived values and send only what the client strictly needs.',
  references: [
    {
      title: 'OWASP - Sensitive Data Exposure',
      url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    },
    {
      title: 'OWASP - Security Misconfiguration',
      url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const ast = context.ast as File;

    /**
     * Check if an ObjectExpression contains a sensitive property key.
     * Only checks the top-level keys (not nested objects) to avoid false positives
     * on things like { user: { password: ... } } where the field might be from a DB model.
     */
    const checkObjectForSensitiveKeys = (
      obj: BabelTypes.ObjectExpression,
      line: number,
      isTokenProp = false,
    ) => {
      for (const prop of obj.properties) {
        if (prop.type !== 'ObjectProperty') continue;

        const key = prop.key;
        const keyName =
          key.type === 'Identifier' ? key.name :
          key.type === 'StringLiteral' ? key.value :
          null;

        if (!keyName) continue;

        const lower = keyName.toLowerCase();

        // Hard secrets — never OK in a response
        if (SENSITIVE_RESPONSE_PROPS.some(p => lower === p.toLowerCase())) {
          findings.push({
            ruleId: 'SEC001',
            severity: 'high',
            category: 'Logging',
            title: 'Sensitive Data in HTTP Response',
            description: `Response body includes sensitive field "${keyName}"`,
            impact: `"${keyName}" in a response body can be intercepted by proxies, stored in browser history, or leaked in logs.`,
            remediation: `Remove "${keyName}" from the response. If a credential must be transmitted, use a short-lived token over HTTPS only.`,
            references: sensitiveResponseRule.references,
            filePath: context.filePath,
            line,
          });
        }

        // Token fields — flag with medium severity (acceptable in auth endpoints,
        // suspicious in general routes)
        if (!isTokenProp && TOKEN_RESPONSE_PROPS.some(p => lower === p.toLowerCase())) {
          findings.push({
            ruleId: 'SEC001',
            severity: 'medium',
            category: 'Logging',
            title: 'Token Sent in HTTP Response',
            description: `Response body includes token field "${keyName}"`,
            impact: `Tokens in response bodies are stored in browser history, JS memory, and can be leaked. Prefer HttpOnly cookies for session tokens.`,
            remediation: `Consider delivering tokens via HttpOnly cookies instead of response body. If using response body, ensure HTTPS, short expiry, and no logging.`,
            references: sensitiveResponseRule.references,
            filePath: context.filePath,
            line,
          });
        }
      }
    };

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;

        // Match res.json(...) / res.send(...) / res.status(...).json(...)
        const isResponseOutput = (() => {
          // res.json(...)
          if (
            callee.type === 'MemberExpression' &&
            callee.property.type === 'Identifier' &&
            (callee.property.name === 'json' || callee.property.name === 'send') &&
            callee.object.type === 'Identifier' &&
            callee.object.name === 'res'
          ) return true;

          // res.status(200).json(...)
          if (
            callee.type === 'MemberExpression' &&
            callee.property.type === 'Identifier' &&
            callee.property.name === 'json' &&
            callee.object.type === 'CallExpression'
          ) {
            const innerCallee = (callee.object as BabelTypes.CallExpression).callee;
            if (
              innerCallee.type === 'MemberExpression' &&
              innerCallee.property.type === 'Identifier' &&
              innerCallee.property.name === 'status' &&
              innerCallee.object.type === 'Identifier' &&
              innerCallee.object.name === 'res'
            ) return true;
          }

          return false;
        })();

        if (!isResponseOutput) return;

        const arg = path.node.arguments[0];
        if (!arg) return;

        const line = getNodeLine(path.node);

        // res.json({ key: value, ... })
        if (arg.type === 'ObjectExpression') {
          checkObjectForSensitiveKeys(arg, line);
        }
      },
    });

    return findings;
  },
};
