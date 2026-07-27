/**
 * express-audit configuration file
 *
 * Copy to express-audit.config.js (or .express-audit.json) in your project root.
 * Supported file names:
 *   - express-audit.config.js / .mjs / .cjs
 *   - .express-audit.json
 *   - .express-auditrc / .express-auditrc.json
 */

/** @type {import('express-audit').AuditConfig} */
export default {
  rules: {
    // Disable specific rules by ID
    disabled: [
      // 'PROD004',  // e.g. disable compression check if using a CDN
    ],

    // Override severity for specific rules
    overrides: {
      // 'HEADER001': { severity: 'medium' }, // promote X-Powered-By to medium
      // 'RATE001':   { severity: 'high' },   // treat missing rate-limit as high
    },
  },

  ignore: {
    // Glob patterns — files matching these are not analysed
    paths: [
      'src/generated/**',
      'src/__mocks__/**',
      '**/*.test.ts',
      '**/*.spec.ts',
    ],

    // Suppress specific rule IDs across the whole project
    rules: [],
  },

  output: {
    // Default format when running without --json / --html / --sarif flags
    // format: 'cli',

    // Write report to a file automatically
    // file: 'reports/security-audit.html',
  },
};
