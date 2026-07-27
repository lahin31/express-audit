import type { AuditResult, Finding, Severity } from '../types/index.js';

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#2563eb',
  info: '#6b7280',
};

const SEVERITY_BG: Record<Severity, string> = {
  critical: '#fee2e2',
  high: '#ffedd5',
  medium: '#fef3c7',
  low: '#dbeafe',
  info: '#f3f4f6',
};

export function generateHTMLReport(result: AuditResult): string {
  const bySeverity: Record<Severity, Finding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    info: [],
  };

  for (const finding of result.findings) {
    bySeverity[finding.severity as Severity].push(finding);
  }

  const scoreColor =
    result.score >= 90 ? '#16a34a' :
    result.score >= 70 ? '#d97706' :
    '#dc2626';

  const findingsHTML = (['critical', 'high', 'medium', 'low', 'info'] as Severity[])
    .filter(sev => bySeverity[sev].length > 0)
    .map(sev => `
      <div class="severity-group">
        <h2 style="color: ${SEVERITY_COLORS[sev]}; border-bottom: 2px solid ${SEVERITY_COLORS[sev]}; padding-bottom: 8px">
          ${sev.charAt(0).toUpperCase() + sev.slice(1)} (${bySeverity[sev].length})
        </h2>
        ${bySeverity[sev].map(finding => `
          <div class="finding" style="border-left: 4px solid ${SEVERITY_COLORS[sev]}; background: ${SEVERITY_BG[sev]}">
            <div class="finding-header">
              <span class="rule-id" style="color: ${SEVERITY_COLORS[sev]}">${finding.ruleId}</span>
              <span class="finding-title">${escapeHtml(finding.title)}</span>
              <span class="badge" style="background: ${SEVERITY_COLORS[sev]}">${sev.toUpperCase()}</span>
            </div>
            ${finding.filePath ? `<div class="location">📁 ${escapeHtml(finding.filePath)}${finding.line ? `:${finding.line}` : ''}</div>` : ''}
            <p class="description">${escapeHtml(finding.description)}</p>
            <div class="impact">
              <strong>Impact:</strong> ${escapeHtml(finding.impact)}
            </div>
            <div class="remediation">
              <strong>Remediation:</strong>
              <pre>${escapeHtml(finding.remediation)}</pre>
            </div>
            ${finding.references.length > 0 ? `
              <div class="references">
                <strong>References:</strong>
                <ul>
                  ${finding.references.map(ref => `<li><a href="${safeHref(ref.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(ref.title)}</a></li>`).join('')}
                </ul>
              </div>
            ` : ''}
          </div>
        `).join('')}
      </div>
    `).join('');

  const categoryScoresHTML = result.categoryScores.map(cat => {
    const color = cat.score >= 90 ? '#16a34a' : cat.score >= 70 ? '#d97706' : '#dc2626';
    return `
      <div class="category-score">
        <span class="category-name">${escapeHtml(cat.category)}</span>
        <div class="progress-bar">
          <div class="progress-fill" style="width: ${cat.score}%; background: ${color}"></div>
        </div>
        <span class="category-percent" style="color: ${color}">${cat.score}%</span>
      </div>
    `;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Express Audit Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f8fafc; color: #1e293b; }
    .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
    header { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); color: white; padding: 32px; border-radius: 12px; margin-bottom: 24px; }
    header h1 { font-size: 2rem; margin-bottom: 8px; }
    header .meta { opacity: 0.7; font-size: 0.875rem; }
    .score-card { background: white; border-radius: 12px; padding: 24px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 24px; }
    .score-value { font-size: 5rem; font-weight: 900; color: ${scoreColor}; line-height: 1; }
    .score-label { color: #6b7280; font-size: 1.25rem; margin-top: 8px; }
    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
    .stat-card { background: white; border-radius: 8px; padding: 16px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .stat-number { font-size: 2rem; font-weight: 700; }
    .stat-label { color: #6b7280; font-size: 0.875rem; margin-top: 4px; }
    .section { background: white; border-radius: 12px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 24px; }
    .section h2 { font-size: 1.25rem; margin-bottom: 16px; color: #1e293b; }
    .finding { padding: 16px; border-radius: 8px; margin-bottom: 12px; }
    .finding-header { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
    .rule-id { font-family: monospace; font-weight: 700; font-size: 0.9rem; }
    .finding-title { font-weight: 600; flex: 1; }
    .badge { padding: 2px 8px; border-radius: 4px; color: white; font-size: 0.75rem; font-weight: 700; }
    .location { font-family: monospace; font-size: 0.8rem; color: #6b7280; margin-bottom: 8px; }
    .description { margin-bottom: 8px; color: #374151; }
    .impact { background: rgba(0,0,0,0.04); padding: 8px; border-radius: 4px; margin-bottom: 8px; font-size: 0.9rem; }
    .remediation { margin-bottom: 8px; font-size: 0.9rem; }
    .remediation pre { background: #f1f5f9; padding: 8px; border-radius: 4px; font-size: 0.85rem; white-space: pre-wrap; margin-top: 4px; }
    .references ul { list-style: none; margin-top: 4px; }
    .references a { color: #2563eb; text-decoration: none; font-size: 0.85rem; }
    .severity-group { margin-bottom: 24px; }
    .category-score { display: flex; align-items: center; gap: 16px; margin-bottom: 12px; }
    .category-name { width: 200px; font-size: 0.9rem; }
    .progress-bar { flex: 1; height: 12px; background: #e5e7eb; border-radius: 6px; overflow: hidden; }
    .progress-fill { height: 100%; border-radius: 6px; transition: width 0.3s; }
    .category-percent { width: 48px; text-align: right; font-weight: 700; font-size: 0.9rem; }
    .casa-note { background: #fef3c7; border: 1px solid #d97706; border-radius: 8px; padding: 16px; margin-bottom: 24px; }
    .casa-note h3 { color: #d97706; margin-bottom: 8px; }
    footer { text-align: center; color: #6b7280; font-size: 0.875rem; margin-top: 24px; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🔒 Express Audit Report</h1>
      <div class="meta">
        Generated: ${new Date(result.timestamp).toLocaleString()} | 
        Project: ${escapeHtml(result.projectRoot)} | 
        Version: ${result.version}
      </div>
    </header>

    <div class="score-card">
      <div class="score-value">${result.score}</div>
      <div class="score-label">Security Score out of 100</div>
      <p class="score-disclaimer">
        The score is a weighted heuristic based on finding severity across rule categories.
        A score of 100 means no findings were detected — it does not mean the application is secure.
        Use it to track improvement over time and to prioritise which findings to address first.
        Do not present it as a security certification.
      </p>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-number" style="color: #dc2626">${bySeverity.critical.length}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card">
        <div class="stat-number" style="color: #ea580c">${bySeverity.high.length}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card">
        <div class="stat-number" style="color: #d97706">${bySeverity.medium.length}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card">
        <div class="stat-number" style="color: #2563eb">${bySeverity.low.length}</div>
        <div class="stat-label">Low</div>
      </div>
    </div>

    ${result.casaNote ? `
      <div class="casa-note">
        <h3>⚠️ Google CASA Readiness Note</h3>
        <p>${escapeHtml(result.casaNote)}</p>
      </div>
    ` : ''}

    <div class="section">
      <h2>📈 Category Scores</h2>
      ${categoryScoresHTML}
    </div>

    <div class="section">
      <h2>🔍 Findings</h2>
      ${findingsHTML || '<p style="color: #6b7280">No findings detected. Great job!</p>'}
    </div>

    <footer>
      Generated by <strong>express-audit</strong> v${escapeHtml(result.version)} · ${result.filesAnalyzed} files analyzed
    </footer>
  </div>
</body>
</html>`;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Validate a URL is safe to use in an href attribute.
 * Only allows https:// and http:// schemes — blocks javascript:, data:, etc.
 */
function safeHref(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
      return escapeHtml(url);
    }
  } catch {
    // fall through
  }
  return '#';
}
