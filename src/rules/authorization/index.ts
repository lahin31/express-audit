export { missingAuthMiddlewareRule, adminRouteUnprotectedRule } from './missing-auth.js';

import { missingAuthMiddlewareRule, adminRouteUnprotectedRule } from './missing-auth.js';
import type { Rule } from '../../types/index.js';

export const authorizationRules: Rule[] = [
  missingAuthMiddlewareRule,
  adminRouteUnprotectedRule,
];
