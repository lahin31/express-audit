import type { AuditResult } from '../types/index.js';

export function generateJSONReport(result: AuditResult): string {
  return JSON.stringify(result, null, 2);
}
