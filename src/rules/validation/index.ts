export { unsafeReqBodyRule, unsafeQueryParamRule } from './input-validation.js';

import { unsafeReqBodyRule, unsafeQueryParamRule } from './input-validation.js';
import type { Rule } from '../../types/index.js';

export const validationRules: Rule[] = [
  unsafeReqBodyRule,
  unsafeQueryParamRule,
];
