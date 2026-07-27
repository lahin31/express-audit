export {
  dockerRunningAsRootRule,
  dockerLatestTagRule,
  dockerHealthcheckRule,
  dockerSecretsInImageRule,
  dockerCopyDotRule,
} from './dockerfile-security.js';

import {
  dockerRunningAsRootRule,
  dockerLatestTagRule,
  dockerHealthcheckRule,
  dockerSecretsInImageRule,
  dockerCopyDotRule,
} from './dockerfile-security.js';
import type { Rule } from '../../types/index.js';

export const dockerRules: Rule[] = [
  dockerRunningAsRootRule,
  dockerLatestTagRule,
  dockerHealthcheckRule,
  dockerSecretsInImageRule,
  dockerCopyDotRule,
];
