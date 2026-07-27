import type { AuditResult, Finding, Severity } from '../types/index.js';
import { relative } from 'path';

interface SarifReport {
  version: string;
  $schema: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string };
  defaultConfiguration: { level: string };
  properties: {
    tags: string[];
    'security-severity': string;
  };
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: {
        startLine: number;
        startColumn?: number;
      };
    };
  }>;
}

const SEVERITY_TO_SARIF_LEVEL: Record<Severity, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

const SEVERITY_TO_SCORE: Record<Severity, string> = {
  critical: '9.0',
  high: '7.0',
  medium: '5.0',
  low: '3.0',
  info: '0.0',
};

export function generateSARIFReport(result: AuditResult): string {
  // Create unique rules
  const rulesMap = new Map<string, SarifRule>();
  for (const finding of result.findings) {
    if (!rulesMap.has(finding.ruleId)) {
      rulesMap.set(finding.ruleId, {
        id: finding.ruleId,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        help: {
          text: `${finding.impact}\n\nRemediation:\n${finding.remediation}\n\nReferences:\n${finding.references.map(r => `${r.title}: ${r.url}`).join('\n')}`,
        },
        defaultConfiguration: {
          level: SEVERITY_TO_SARIF_LEVEL[finding.severity],
        },
        properties: {
          tags: [finding.category, finding.severity],
          'security-severity': SEVERITY_TO_SCORE[finding.severity],
        },
      });
    }
  }

  // Create results
  const sarifResults: SarifResult[] = result.findings.map((finding: Finding) => {
    const sarifResult: SarifResult = {
      ruleId: finding.ruleId,
      level: SEVERITY_TO_SARIF_LEVEL[finding.severity],
      message: { text: finding.description },
    };

    if (finding.filePath) {
      const relPath = relative(result.projectRoot, finding.filePath);
      sarifResult.locations = [
        {
          physicalLocation: {
            artifactLocation: { uri: relPath },
            ...(finding.line
              ? {
                  region: {
                    startLine: finding.line,
                    startColumn: finding.column || 1,
                  },
                }
              : {}),
          },
        },
      ];
    }

    return sarifResult;
  });

  const sarif: SarifReport = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'express-audit',
            version: result.version,
            informationUri: 'https://github.com/yourusername/express-audit',
            rules: Array.from(rulesMap.values()),
          },
        },
        results: sarifResults,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
