/**
 * express-audit - Deterministic security auditor for Express.js applications
 *
 * Public API for programmatic use
 */

export { AuditEngine } from './core/engine.js';
export { allRules, authenticationRules, authorizationRules, httpSecurityRules, cookiesRules, corsRules, rateLimitingRules, secretsRules, sqlRules, loggingRules, validationRules, oauthRules, casaRules, productionRules, dockerRules, errorHandlingRules } from './rules/index.js';
export { generateCLIReport, generateJSONReport, generateHTMLReport, generateSARIFReport } from './reporters/index.js';
export type { AuditResult, Finding, Rule, RuleContext, AuditConfig, Severity, CategoryScore } from './types/index.js';

import { AuditEngine } from './core/engine.js';
import { allRules } from './rules/index.js';
import type { AuditConfig, AuditResult } from './types/index.js';

/**
 * Run a full audit on a project directory.
 * This is the main convenience function for programmatic use.
 *
 * @example
 * import { audit } from 'express-audit';
 * const result = await audit('./my-express-app');
 * console.log(`Score: ${result.score}/100`);
 */
export async function audit(projectRoot: string, config: AuditConfig = {}): Promise<AuditResult> {
  const engine = new AuditEngine(config);
  engine.registerRules(allRules);
  return engine.audit(projectRoot);
}
