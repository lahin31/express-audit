export { unsafeReqBodyRule, unsafeQueryParamRule } from './input-validation.js';
export { prototypePollutionMergeRule } from './prototype-pollution.js';
export { codeInjectionRule } from './code-injection.js';

import { unsafeReqBodyRule, unsafeQueryParamRule } from './input-validation.js';
import { prototypePollutionMergeRule } from './prototype-pollution.js';
import { codeInjectionRule } from './code-injection.js';
import type { Rule } from '../../types/index.js';

export const validationRules: Rule[] = [
  unsafeReqBodyRule,
  unsafeQueryParamRule,
  prototypePollutionMergeRule,
  codeInjectionRule,
];
