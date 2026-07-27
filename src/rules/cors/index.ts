export { corsWildcardRule } from './cors-wildcard.js';

import { corsWildcardRule } from './cors-wildcard.js';
import type { Rule } from '../../types/index.js';

export const corsRules: Rule[] = [
  corsWildcardRule,
];
