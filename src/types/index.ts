// Core type definitions for express-audit

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type DetectorType = 'ast' | 'regex' | 'file' | 'config' | 'dependency';

export type ReportFormat = 'cli' | 'json' | 'html' | 'sarif' | 'github';

export interface RuleReference {
  title: string;
  url: string;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  impact: string;
  remediation: string;
  references: RuleReference[];
  filePath?: string;
  line?: number;
  column?: number;
  snippet?: string;
  metadata?: Record<string, unknown>;
}

export interface RuleContext {
  filePath: string;
  source: string;
  ast?: unknown;
  projectRoot: string;
  allFiles: string[];
  config: AuditConfig;
}

export interface Rule {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  detectorType: DetectorType;
  references: RuleReference[];
  remediation: string;
  run(context: RuleContext): Finding[];
}

export interface CategoryScore {
  category: string;
  score: number;
  total: number;
  findings: number;
  criticalFindings: number;
  highFindings: number;
}

export interface AuditResult {
  projectRoot: string;
  timestamp: string;
  version: string;
  score: number;
  categoryScores: CategoryScore[];
  findings: Finding[];
  totalFiles: number;
  filesAnalyzed: number;
  casaNote?: string;
}

export interface AuditConfig {
  rules?: {
    disabled?: string[];
    overrides?: Record<string, { severity?: Severity }>;
  };
  ignore?: {
    paths?: string[];
    rules?: string[];
  };
  output?: {
    format?: ReportFormat;
    file?: string;
  };
}

export interface PluginRule extends Rule {
  pluginName: string;
}

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 10,
  medium: 5,
  low: 2,
  info: 0,
};

export const CATEGORY_WEIGHTS: Record<string, number> = {
  Authentication: 15,
  Authorization: 15,
  'Input Validation': 10,
  'SQL Security': 10,
  'HTTP Security': 10,
  Cookies: 8,
  Sessions: 8,
  CORS: 8,
  'Rate Limiting': 5,
  Secrets: 10,
  Logging: 5,
  'Error Handling': 5,
  OAuth: 8,
  'CASA Readiness': 8,
  'Production Readiness': 7,
  Docker: 5,
};
