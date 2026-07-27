import chalk from 'chalk';
import type { AuditResult, Finding, Severity } from '../types/index.js';

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: '🔴',
  high: '⚠️ ',
  medium: '📋',
  low: 'ℹ️ ',
  info: '💡',
};

export function generateCLIReport(result: AuditResult): string {
  const lines: string[] = [];

  // Header
  lines.push('');
  lines.push(chalk.bold.cyan('Express Audit v1.0.0'));
  lines.push('');

  // Score
  const scoreColor =
    result.score >= 90 ? chalk.green :
    result.score >= 70 ? chalk.yellow :
    chalk.red;

  lines.push(chalk.bold(`📊 Security Score: ${scoreColor(result.score.toString())}/100`));
  lines.push('');
  lines.push(
    chalk.dim(
      'The score is a weighted heuristic. A score of 100 does not mean the application is secure;\n' +
      'a low score does not mean it is insecure. Use it to track progress and prioritise fixes.',
    ),
  );
  lines.push('');

  // Group findings by severity
  const bySeverity: Record<string, Finding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    info: [],
  };

  for (const finding of result.findings) {
    bySeverity[finding.severity].push(finding);
  }

  // Display each severity group
  for (const [severity, findings] of Object.entries(bySeverity)) {
    if (findings.length === 0) continue;

    const sev = severity as Severity;
    const icon = SEVERITY_ICONS[sev];
    const color = SEVERITY_COLORS[sev];

    lines.push(color(`${icon} ${severity.charAt(0).toUpperCase() + severity.slice(1)} (${findings.length})`));
    lines.push(color('─'.repeat(60)));

    for (const finding of findings) {
      lines.push(color(`${finding.ruleId} | ${finding.title}`));
      if (finding.filePath) {
        const location = finding.line
          ? `${finding.filePath}:${finding.line}`
          : finding.filePath;
        lines.push(chalk.gray(`Location: ${location}`));
      }
      lines.push(chalk.gray(`Impact: ${finding.impact}`));
      lines.push(chalk.gray(`Fix: ${finding.remediation}`));
      lines.push('');
    }
  }

  // Category scores
  if (result.categoryScores.length > 0) {
    lines.push(chalk.bold('📈 Category Scores'));
    lines.push('─'.repeat(60));
    
    for (const cat of result.categoryScores) {
      const scoreColor =
        cat.score >= 90 ? chalk.green :
        cat.score >= 70 ? chalk.yellow :
        chalk.red;

      const bar = '█'.repeat(Math.floor(cat.score / 5)) + '░'.repeat(20 - Math.floor(cat.score / 5));
      lines.push(`${cat.category.padEnd(25)} ${scoreColor(cat.score.toString().padStart(3))}% ${bar}`);
    }
    lines.push('');
  }

  // CASA note if applicable
  if (result.casaNote) {
    lines.push(chalk.yellow.bold('⚠️  Google CASA Readiness'));
    lines.push(chalk.yellow('─'.repeat(60)));
    lines.push(chalk.yellow(result.casaNote));
    lines.push('');
  }

  // Summary
  lines.push(chalk.bold('Summary'));
  lines.push('-'.repeat(60));
  lines.push(`Total files scanned: ${result.filesAnalyzed}`);
  lines.push(`Total findings: ${result.findings.length}`);
  lines.push(`Critical: ${bySeverity.critical.length}`);
  lines.push(`High: ${bySeverity.high.length}`);
  lines.push(`Medium: ${bySeverity.medium.length}`);
  lines.push(`Low: ${bySeverity.low.length}`);
  lines.push('');

  return lines.join('\n');
}
