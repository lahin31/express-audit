export { sqlInjectionRule, prismaUnsafeRule } from './sql-injection.js';

import { sqlInjectionRule, prismaUnsafeRule } from './sql-injection.js';
import type { Rule } from '../../types/index.js';

export const sqlRules: Rule[] = [
  sqlInjectionRule,
  prismaUnsafeRule,
];
