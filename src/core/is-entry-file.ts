import { relative } from 'path';

/**
 * Returns true only for likely application entry files.
 *
 * Criteria (all must pass):
 *  1. Filename is one of: app, server, main, index — with .ts/.js extension
 *  2. The file sits at the project root or one directory deep (e.g. src/)
 *     — rules out src/router/index.ts, src/middlewares/auth.ts, etc.
 *  3. The source contains at least one Express app signal
 *     — rules out barrel/re-export files that share a name but no app code
 */
export function isEntryFile(
  filePath: string,
  projectRoot: string,
  source: string,
): boolean {
  const rel = relative(projectRoot, filePath).replace(/\\/g, '/');

  // 1. Known entry filename
  const knownNames = [
    'app.ts', 'app.js',
    'server.ts', 'server.js',
    'main.ts', 'main.js',
    'index.ts', 'index.js',
  ];
  const basename = rel.split('/').pop() ?? '';
  if (!knownNames.includes(basename)) return false;

  // 2. At root level or one directory deep only
  const depth = rel.split('/').length;
  if (depth > 2) return false;

  // 3. Contains evidence of an Express app being configured
  return (
    source.includes('express()') ||
    source.includes('createServer') ||
    source.includes('app.listen') ||
    source.includes('app.use(') ||
    source.includes('app.get(') ||
    source.includes('app.post(')
  );
}
