export {
  healthEndpointRule,
  gracefulShutdownRule,
  trustProxyRule,
  compressionMissingRule,
} from './production-readiness.js';

import {
  healthEndpointRule,
  gracefulShutdownRule,
  trustProxyRule,
  compressionMissingRule,
} from './production-readiness.js';
import type { Rule } from '../../types/index.js';

export const productionRules: Rule[] = [
  healthEndpointRule,
  gracefulShutdownRule,
  trustProxyRule,
  compressionMissingRule,
];
