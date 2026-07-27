export {
  casaRefreshTokenStorageRule,
  casaTokenRevocationRule,
  casaOauthCredentialsLoggedRule,
  casaAuditLoggingRule,
  casaNonceRule,
} from './casa-checks.js';

import {
  casaRefreshTokenStorageRule,
  casaTokenRevocationRule,
  casaOauthCredentialsLoggedRule,
  casaAuditLoggingRule,
  casaNonceRule,
} from './casa-checks.js';
import type { Rule } from '../../types/index.js';

export const casaRules: Rule[] = [
  casaRefreshTokenStorageRule,
  casaTokenRevocationRule,
  casaOauthCredentialsLoggedRule,
  casaAuditLoggingRule,
  casaNonceRule,
];
