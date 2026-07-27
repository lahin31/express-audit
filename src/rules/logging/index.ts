export { sensitiveLoggingRule, stackTraceExposureRule } from './sensitive-logging.js';

import { sensitiveLoggingRule, stackTraceExposureRule } from './sensitive-logging.js';
import type { Rule } from '../../types/index.js';

export const loggingRules: Rule[] = [
  sensitiveLoggingRule,
  stackTraceExposureRule,
];
