export { rawErrorResponseRule, missingErrorHandlerRule } from './error-handling.js';

import { rawErrorResponseRule, missingErrorHandlerRule } from './error-handling.js';
import type { Rule } from '../../types/index.js';

export const errorHandlingRules: Rule[] = [
  rawErrorResponseRule,
  missingErrorHandlerRule,
];
