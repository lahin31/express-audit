import { existsSync, readFileSync } from 'fs';
import { resolve, join } from 'path';
import type { AuditConfig } from '../types/index.js';

const CONFIG_FILE_NAMES = [
  'express-audit.config.js',
  'express-audit.config.mjs',
  'express-audit.config.cjs',
  '.express-audit.json',
  '.express-auditrc',
  '.express-auditrc.json',
];

/**
 * Load audit configuration from a file in the project root.
 * Searches for config files in priority order.
 * Returns an empty config object if none found.
 */
export async function loadConfig(projectRoot: string): Promise<AuditConfig> {
  for (const name of CONFIG_FILE_NAMES) {
    const filePath = join(projectRoot, name);
    if (!existsSync(filePath)) continue;

    try {
      if (name.endsWith('.json') || name === '.express-auditrc') {
        const raw = readFileSync(filePath, 'utf-8');
        return JSON.parse(raw) as AuditConfig;
      }

      // JS config — dynamic import
      const mod = await import(filePath);
      return (mod.default ?? mod) as AuditConfig;
    } catch (err) {
      console.error(`[express-audit] Failed to load config from ${filePath}:`, err);
    }
  }

  return {};
}

/**
 * Merge CLI options into a file-based config.
 * CLI options take precedence.
 */
export function mergeConfig(
  fileConfig: AuditConfig,
  cliOptions: Partial<AuditConfig>,
): AuditConfig {
  return {
    rules: {
      disabled: [
        ...(fileConfig.rules?.disabled ?? []),
        ...(cliOptions.rules?.disabled ?? []),
      ],
      overrides: {
        ...(fileConfig.rules?.overrides ?? {}),
        ...(cliOptions.rules?.overrides ?? {}),
      },
    },
    ignore: {
      paths: [
        ...(fileConfig.ignore?.paths ?? []),
        ...(cliOptions.ignore?.paths ?? []),
      ],
      rules: [
        ...(fileConfig.ignore?.rules ?? []),
        ...(cliOptions.ignore?.rules ?? []),
      ],
    },
    output: {
      ...(fileConfig.output ?? {}),
      ...(cliOptions.output ?? {}),
    },
  };
}
