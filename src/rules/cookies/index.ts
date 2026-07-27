export { cookieSecurityRule } from './cookie-security.js';
export { sessionSecurityRule } from './session-security.js';

import { cookieSecurityRule } from './cookie-security.js';
import { sessionSecurityRule } from './session-security.js';
import type { Rule } from '../../types/index.js';

export const cookiesRules: Rule[] = [
  cookieSecurityRule,
  sessionSecurityRule,
];
