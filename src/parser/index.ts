import * as babelParser from '@babel/parser';
import type { File } from '@babel/types';
import { readFileSync, existsSync } from 'fs';

export interface ParseResult {
  ast: File | null;
  source: string;
  error?: string;
}

/**
 * Parse a JavaScript or TypeScript file into an AST.
 * Returns null AST if parsing fails (e.g., non-JS files).
 */
export function parseFile(filePath: string): ParseResult {
  if (!existsSync(filePath)) {
    return { ast: null, source: '', error: 'File not found' };
  }

  let source: string;
  try {
    source = readFileSync(filePath, 'utf-8');
  } catch (err) {
    return { ast: null, source: '', error: `Cannot read file: ${err}` };
  }

  // Skip very large files (>2MB) to keep analysis fast
  if (source.length > 2_000_000) {
    return { ast: null, source, error: 'File too large, skipping AST parse' };
  }

  try {
    const ast = babelParser.parse(source, {
      sourceType: 'unambiguous',
      allowImportExportEverywhere: true,
      allowReturnOutsideFunction: true,
      allowSuperOutsideMethod: true,
      plugins: [
        'typescript',
        'jsx',
        'decorators-legacy',
        'classProperties',
        'classPrivateProperties',
        'classPrivateMethods',
        'dynamicImport',
        'exportDefaultFrom',
        'exportNamespaceFrom',
        'nullishCoalescingOperator',
        'optionalChaining',
        'optionalCatchBinding',
        'logicalAssignment',
        'numericSeparator',
        'bigInt',
      ],
    });
    return { ast, source };
  } catch {
    // Fall back: try plain JS parsing without TypeScript plugin
    try {
      const ast = babelParser.parse(source, {
        sourceType: 'unambiguous',
        allowImportExportEverywhere: true,
        allowReturnOutsideFunction: true,
        plugins: ['jsx', 'dynamicImport', 'classProperties'],
      });
      return { ast, source };
    } catch (err2) {
      return { ast: null, source, error: `Parse error: ${err2}` };
    }
  }
}

/**
 * Get line number from character offset in source
 */
export function getLineFromOffset(source: string, offset: number): number {
  const lines = source.slice(0, offset).split('\n');
  return lines.length;
}

/**
 * Extract a code snippet around a given line
 */
export function getSnippet(source: string, line: number, contextLines = 2): string {
  const lines = source.split('\n');
  const start = Math.max(0, line - contextLines - 1);
  const end = Math.min(lines.length, line + contextLines);
  return lines
    .slice(start, end)
    .map((l, i) => `${start + i + 1} | ${l}`)
    .join('\n');
}
