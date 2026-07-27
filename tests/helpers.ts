import { parseFile } from '../src/parser/index.js';
import type { RuleContext, AuditConfig } from '../src/types/index.js';
import { writeFileSync, mkdirSync } from 'fs';
import { join, basename } from 'path';
import { tmpdir } from 'os';

/**
 * Creates a temporary file with the given source code and returns a RuleContext.
 * The filePath is always a flat file in tmpdir — no subdirectory creation.
 */
export function createContext(
  source: string,
  fileName = 'test-app.ts',
  config: AuditConfig = {},
): RuleContext {
  // Flatten any path separators so we never try to create intermediate dirs
  const safeName = basename(fileName);
  const filePath = join(tmpdir(), `ea-${Date.now()}-${safeName}`);
  writeFileSync(filePath, source, 'utf-8');

  const { ast } = parseFile(filePath);

  return {
    filePath,
    source,
    ast: ast ?? undefined,
    projectRoot: tmpdir(),
    allFiles: [filePath],
    config,
  };
}

/**
 * Like createContext but lets the caller specify a fixture name that rules use
 * for path-based checks (e.g. "app.js", "server.ts", "Dockerfile").
 * The actual file on disk keeps the flat safe name; filePath is overridden to
 * look like the fixture name so rules that inspect the path behave correctly.
 */
export function createContextFromFixture(
  source: string,
  fixtureName: string,
  config: AuditConfig = {},
): RuleContext {
  const ctx = createContext(source, basename(fixtureName), config);
  // Override filePath to the fixture name so path-checking rules work
  return { ...ctx, filePath: join(tmpdir(), fixtureName) };
}
