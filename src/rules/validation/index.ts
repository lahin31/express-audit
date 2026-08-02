export { unsafeReqBodyRule, unsafeQueryParamRule } from './input-validation.js';
export { prototypePollutionMergeRule } from './prototype-pollution.js';

import { unsafeReqBodyRule, unsafeQueryParamRule } from './input-validation.js';
import { prototypePollutionMergeRule } from './prototype-pollution.js';
import type { Rule } from '../../types/index.js';

export const validationRules: Rule[] = [
  unsafeReqBodyRule,
  unsafeQueryParamRule,
  prototypePollutionMergeRule,
];
