/**
 * Helpers for generating remediation strings that work for both
 * ESM (TypeScript / "type":"module") and CJS ("require") projects.
 */

/**
 * Returns a remediation snippet showing both ESM and CJS import styles.
 *
 * @param pkg        npm package name, e.g. "express-rate-limit"
 * @param identifier local identifier to bind, e.g. "rateLimit"
 * @param usage      code after the import, e.g. "app.use(rateLimit(...))"
 * @param named      if true uses named import syntax: import { identifier } from 'pkg'
 *
 * @example
 * bothStyles('helmet', 'helmet', 'app.use(helmet());')
 * bothStyles('express-rate-limit', 'rateLimit', 'app.use(rateLimit({ max: 100 }));', true)
 */
export function bothStyles(
  pkg: string,
  identifier: string,
  usage: string,
  named = false,
): string {
  const esmBinding = named ? `{ ${identifier} }` : identifier;
  const cjsBinding = named ? `{ ${identifier} }` : identifier;
  return (
    `// ESM / TypeScript\n` +
    `import ${esmBinding} from '${pkg}';\n` +
    `${usage}\n\n` +
    `// CommonJS\n` +
    `const ${cjsBinding} = require('${pkg}');\n` +
    `${usage}`
  );
}
