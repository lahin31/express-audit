export { jwtHardcodedRule } from './jwt-hardcoded.js';
export { jwtNoExpiryRule } from './jwt-no-expiry.js';
export { weakBcryptRule } from './weak-bcrypt.js';
export { plaintextPasswordRule } from './plaintext-password.js';

import { jwtHardcodedRule } from './jwt-hardcoded.js';
import { jwtNoExpiryRule } from './jwt-no-expiry.js';
import { weakBcryptRule } from './weak-bcrypt.js';
import { plaintextPasswordRule } from './plaintext-password.js';
import type { Rule } from '../../types/index.js';

export const authenticationRules: Rule[] = [
  jwtHardcodedRule,
  jwtNoExpiryRule,
  weakBcryptRule,
  plaintextPasswordRule,
];
