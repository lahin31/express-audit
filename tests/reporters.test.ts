import { describe, it, expect } from 'vitest';
import { generateCLIReport } from '../src/reporters/cli-reporter.js';
import { generateJSONReport } from '../src/reporters/json-reporter.js';
import { generateHTMLReport } from '../src/reporters/html-reporter.js';
import { generateSARIFReport } from '../src/reporters/sarif-reporter.js';
import type { AuditResult } from '../src/types/index.js';

const mockResult: AuditResult = {
  projectRoot: '/project',
  timestamp: '2024-01-01T00:00:00.000Z',
  version: '1.0.0',
  score: 72,
  categoryScores: [
    { category: 'Authentication', score: 50, total: 100, findings: 2, criticalFindings: 1, highFindings: 1 },
    { category: 'CORS', score: 90, total: 100, findings: 0, criticalFindings: 0, highFindings: 0 },
  ],
  findings: [
    {
      ruleId: 'JWT001',
      severity: 'critical',
      category: 'Authentication',
      title: 'Hardcoded JWT Secret',
      description: 'JWT secret is hardcoded',
      impact: 'Allows token forgery',
      remediation: 'Use process.env.JWT_SECRET',
      references: [{ title: 'OWASP', url: 'https://owasp.org' }],
      filePath: '/project/src/auth.ts',
      line: 18,
    },
    {
      ruleId: 'CORS001',
      severity: 'high',
      category: 'CORS',
      title: 'CORS Wildcard',
      description: 'cors() allows all origins',
      impact: 'Any site can make API requests',
      remediation: 'Specify allowed origins',
      references: [],
      filePath: '/project/src/app.ts',
    },
  ],
  totalFiles: 12,
  filesAnalyzed: 12,
  casaNote: 'These are Google CASA readiness checks only.',
};

describe('CLI Reporter', () => {
  it('produces a non-empty string', () => {
    const out = generateCLIReport(mockResult);
    expect(typeof out).toBe('string');
    expect(out.length).toBeGreaterThan(0);
  });

  it('includes the score', () => {
    expect(generateCLIReport(mockResult)).toContain('72');
  });

  it('includes rule IDs', () => {
    const out = generateCLIReport(mockResult);
    expect(out).toContain('JWT001');
    expect(out).toContain('CORS001');
  });

  it('includes CASA note', () => {
    expect(generateCLIReport(mockResult)).toContain('CASA');
  });
});

describe('JSON Reporter', () => {
  it('produces valid JSON', () => {
    const out = generateJSONReport(mockResult);
    expect(() => JSON.parse(out)).not.toThrow();
  });

  it('includes score and findings', () => {
    const parsed = JSON.parse(generateJSONReport(mockResult));
    expect(parsed.score).toBe(72);
    expect(parsed.findings).toHaveLength(2);
  });
});

describe('HTML Reporter', () => {
  it('produces an HTML document', () => {
    const out = generateHTMLReport(mockResult);
    expect(out).toContain('<!DOCTYPE html>');
    expect(out).toContain('</html>');
  });

  it('includes score and rule IDs', () => {
    const out = generateHTMLReport(mockResult);
    expect(out).toContain('72');
    expect(out).toContain('JWT001');
  });

  it('escapes HTML entities to prevent XSS in report', () => {
    const xssResult: AuditResult = {
      ...mockResult,
      findings: [
        {
          ...mockResult.findings[0],
          description: '<script>alert("xss")</script>',
        },
      ],
    };
    const out = generateHTMLReport(xssResult);
    expect(out).not.toContain('<script>alert("xss")</script>');
    expect(out).toContain('&lt;script&gt;');
  });
});

describe('SARIF Reporter', () => {
  it('produces valid JSON', () => {
    const out = generateSARIFReport(mockResult);
    expect(() => JSON.parse(out)).not.toThrow();
  });

  it('has correct SARIF version', () => {
    const parsed = JSON.parse(generateSARIFReport(mockResult));
    expect(parsed.version).toBe('2.1.0');
  });

  it('includes rules and results', () => {
    const parsed = JSON.parse(generateSARIFReport(mockResult));
    const run = parsed.runs[0];
    expect(run.tool.driver.rules.length).toBeGreaterThan(0);
    expect(run.results.length).toBe(2);
  });

  it('maps critical to error level', () => {
    const parsed = JSON.parse(generateSARIFReport(mockResult));
    const criticalResult = parsed.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'JWT001');
    expect(criticalResult.level).toBe('error');
  });
});
