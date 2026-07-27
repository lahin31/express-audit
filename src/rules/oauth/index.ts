export { oauthPkceRule, oauthStateMissingRule, oauthBroadScopesRule } from './oauth-security.js';

import { oauthPkceRule, oauthStateMissingRule, oauthBroadScopesRule } from './oauth-security.js';
import type { Rule } from '../../types/index.js';

export const oauthRules: Rule[] = [
  oauthPkceRule,
  oauthStateMissingRule,
  oauthBroadScopesRule,
];
