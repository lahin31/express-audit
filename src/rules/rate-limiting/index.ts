export { rateLimitMissingRule } from './rate-limit-missing.js';

import { rateLimitMissingRule } from './rate-limit-missing.js';
import type { Rule } from '../../types/index.js';

export const rateLimitingRules: Rule[] = [
  rateLimitMissingRule,
];
