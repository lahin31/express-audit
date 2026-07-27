import type { Rule, RuleContext, Finding } from '../../types/index.js';
import { getSnippet } from '../../parser/index.js';
import { basename } from 'path';

interface SecretPattern {
  id: string;
  title: string;
  regex: RegExp;
  severity: 'critical' | 'high';
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'SECRET001',
    title: 'AWS Access Key',
    regex: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
  },
  {
    id: 'SECRET002',
    title: 'AWS Secret Access Key',
    regex: /(?:aws_secret_access_key|aws_secret)\s*[=:]\s*["']?([A-Za-z0-9/+]{40})["']?/gi,
    severity: 'critical',
  },
  {
    id: 'SECRET003',
    title: 'Google API Key',
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: 'critical',
  },
  {
    id: 'SECRET004',
    title: 'Stripe Secret Key',
    regex: /sk_(live|test)_[0-9a-zA-Z]{24,}/g,
    severity: 'critical',
  },
  {
    id: 'SECRET005',
    title: 'Stripe Publishable Key',
    regex: /pk_(live|test)_[0-9a-zA-Z]{24,}/g,
    severity: 'high',
  },
  {
    id: 'SECRET006',
    title: 'GitHub Token',
    regex: /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
    severity: 'critical',
  },
  {
    id: 'SECRET007',
    title: 'Private Key',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'critical',
  },
  {
    id: 'SECRET008',
    title: 'Hardcoded Password in Variable',
    regex: /(?:password|passwd|pass|secret)\s*[=:]\s*["']([^"'${}]{8,})["']/gi,
    severity: 'high',
  },
  {
    id: 'SECRET009',
    title: 'Hardcoded Database Connection String',
    regex: /(?:mongodb|mysql|postgres|postgresql):\/\/[^:]+:[^@]+@/gi,
    severity: 'critical',
  },
  {
    id: 'SECRET010',
    title: 'Sendgrid API Key',
    regex: /SG\.[A-Za-z0-9\-._]{22}\.[A-Za-z0-9\-._]{43}/g,
    severity: 'critical',
  },
];

export const hardcodedSecretsRule: Rule = {
  id: 'SECRET001',
  severity: 'critical',
  category: 'Secrets',
  title: 'Hardcoded Secret Detected',
  description: 'Sensitive credentials or API keys found hardcoded in source code',
  detectorType: 'regex',
  remediation: 'Move all secrets to environment variables or a secrets manager. Use process.env.SECRET_NAME',
  references: [
    {
      title: 'OWASP - Hardcoded Credentials',
      url: 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
    },
    {
      title: 'CWE-798: Use of Hard-coded Credentials',
      url: 'https://cwe.mitre.org/data/definitions/798.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    const { source, filePath } = context;

    // Skip .env files (those are expected to have secrets) and test fixtures
    const base = basename(filePath).toLowerCase();
    const skipBases = ['.env', 'fixture', 'mock', 'spec'];
    if (skipBases.some(s => base.includes(s))) return [];

    // Skip actual .env files regardless of prefix
    if (base.startsWith('.env') || base.endsWith('.env')) return [];

    const findings: Finding[] = [];
    const lines = source.split('\n');

    for (const pattern of SECRET_PATTERNS) {
      pattern.regex.lastIndex = 0; // Reset regex state

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];

        // Skip comments
        if (line.trim().startsWith('//') || line.trim().startsWith('#') || line.trim().startsWith('*')) {
          continue;
        }

        // Skip process.env references
        if (line.includes('process.env')) continue;

        pattern.regex.lastIndex = 0;
        const match = pattern.regex.exec(line);
        
        if (match) {
          const snippet = getSnippet(source, lineNum + 1, 1);
          findings.push({
            ruleId: pattern.id,
            severity: pattern.severity,
            category: 'Secrets',
            title: pattern.title,
            description: `${pattern.title} found in source code`,
            impact: 'Hardcoded credentials can be extracted from source code, version control history, or compiled bundles.',
            remediation: 'Use environment variables: process.env.SECRET_NAME or a secrets manager like AWS Secrets Manager or HashiCorp Vault.',
            references: hardcodedSecretsRule.references,
            filePath,
            line: lineNum + 1,
            snippet,
          });
        }
      }
    }

    return findings;
  },
};
