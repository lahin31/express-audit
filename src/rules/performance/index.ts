export { nPlusOneQueryRule } from './n-plus-one.js';

import { nPlusOneQueryRule } from './n-plus-one.js';
import type { Rule } from '../../types/index.js';

export const performanceRules: Rule[] = [
  nPlusOneQueryRule,
];
