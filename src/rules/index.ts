import { authenticationRules } from './authentication/index.js';
import { authorizationRules } from './authorization/index.js';
import { httpSecurityRules } from './http-security/index.js';
import { cookiesRules } from './cookies/index.js';
import { corsRules } from './cors/index.js';
import { rateLimitingRules } from './rate-limiting/index.js';
import { secretsRules } from './secrets/index.js';
import { sqlRules } from './sql/index.js';
import { loggingRules } from './logging/index.js';
import { validationRules } from './validation/index.js';
import { oauthRules } from './oauth/index.js';
import { casaRules } from './casa/index.js';
import { productionRules } from './production/index.js';
import { dockerRules } from './docker/index.js';
import { errorHandlingRules } from './error-handling/index.js';
import type { Rule } from '../types/index.js';

export const allRules: Rule[] = [
  ...authenticationRules,
  ...authorizationRules,
  ...httpSecurityRules,
  ...cookiesRules,
  ...corsRules,
  ...rateLimitingRules,
  ...secretsRules,
  ...sqlRules,
  ...loggingRules,
  ...validationRules,
  ...oauthRules,
  ...casaRules,
  ...productionRules,
  ...dockerRules,
  ...errorHandlingRules,
];

export {
  authenticationRules,
  authorizationRules,
  httpSecurityRules,
  cookiesRules,
  corsRules,
  rateLimitingRules,
  secretsRules,
  sqlRules,
  loggingRules,
  validationRules,
  oauthRules,
  casaRules,
  productionRules,
  dockerRules,
  errorHandlingRules,
};
