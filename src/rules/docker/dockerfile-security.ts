import type { Rule, RuleContext, Finding } from '../../types/index.js';

/**
 * Analyze Dockerfile security patterns
 */
export const dockerRunningAsRootRule: Rule = {
  id: 'DOCKER001',
  severity: 'high',
  category: 'Docker',
  title: 'Container Running as Root',
  description: 'Dockerfile does not specify a non-root USER',
  detectorType: 'file',
  remediation: 'Add USER instruction: USER node',
  references: [
    {
      title: 'Docker Security Best Practices',
      url: 'https://docs.docker.com/develop/security-best-practices/',
    },
    {
      title: 'OWASP Docker Security Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html',
    },
    {
      title: 'OWASP Top 10 2021 – A05: Security Misconfiguration',
      url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    },
    {
      title: 'CWE-250: Execution with Unnecessary Privileges',
      url: 'https://cwe.mitre.org/data/definitions/250.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.filePath.toLowerCase().includes('dockerfile')) return [];

    const { source } = context;
    const hasUserInstruction = /^USER\s+[^\s]/m.test(source);
    const hasRootUser = /^USER\s+root/m.test(source);

    if (!hasUserInstruction || hasRootUser) {
      return [{
        ruleId: 'DOCKER001',
        severity: 'high',
        category: 'Docker',
        title: 'Container Running as Root',
        description: 'Dockerfile does not configure a non-root user',
        impact: 'Containers running as root have unnecessary privileges, increasing attack impact if compromised.',
        remediation: 'Add: USER node (after installing dependencies)',
        references: dockerRunningAsRootRule.references,
        filePath: context.filePath,
      }];
    }

    return [];
  },
};

export const dockerLatestTagRule: Rule = {
  id: 'DOCKER002',
  severity: 'medium',
  category: 'Docker',
  title: 'Using Latest Tag',
  description: 'Dockerfile uses :latest tag instead of a specific version',
  detectorType: 'file',
  remediation: 'Pin specific versions: FROM node:20-alpine',
  references: [
    {
      title: 'Docker Best Practices',
      url: 'https://docs.docker.com/develop/dev-best-practices/',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.filePath.toLowerCase().includes('dockerfile')) return [];

    const { source } = context;
    const lines = source.split('\n');

    const findings: Finding[] = [];

    lines.forEach((line, idx) => {
      const fromMatch = /^FROM\s+([^\s]+)/i.exec(line);
      if (fromMatch) {
        const image = fromMatch[1];
        if (image.endsWith(':latest') || !image.includes(':')) {
          findings.push({
            ruleId: 'DOCKER002',
            severity: 'medium',
            category: 'Docker',
            title: 'Using Latest Tag',
            description: `Base image "${image}" uses :latest or unspecified tag`,
            impact: 'Using :latest can introduce breaking changes without warning and makes builds non-reproducible.',
            remediation: 'Pin version: FROM node:20-alpine',
            references: dockerLatestTagRule.references,
            filePath: context.filePath,
            line: idx + 1,
          });
        }
      }
    });

    return findings;
  },
};

export const dockerHealthcheckRule: Rule = {
  id: 'DOCKER003',
  severity: 'low',
  category: 'Docker',
  title: 'Missing HEALTHCHECK',
  description: 'Dockerfile does not define a HEALTHCHECK instruction',
  detectorType: 'file',
  remediation: 'Add HEALTHCHECK: HEALTHCHECK --interval=30s CMD node healthcheck.js',
  references: [
    {
      title: 'Docker HEALTHCHECK',
      url: 'https://docs.docker.com/engine/reference/builder/#healthcheck',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.filePath.toLowerCase().includes('dockerfile')) return [];

    const { source } = context;
    const hasHealthcheck = /^HEALTHCHECK/m.test(source);

    if (!hasHealthcheck) {
      return [{
        ruleId: 'DOCKER003',
        severity: 'low',
        category: 'Docker',
        title: 'Missing HEALTHCHECK',
        description: 'Dockerfile does not configure a HEALTHCHECK',
        impact: 'Without HEALTHCHECK, orchestrators cannot verify if the container is healthy.',
        remediation: 'Add: HEALTHCHECK --interval=30s --timeout=3s CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1',
        references: dockerHealthcheckRule.references,
        filePath: context.filePath,
      }];
    }

    return [];
  },
};

export const dockerSecretsInImageRule: Rule = {
  id: 'DOCKER004',
  severity: 'critical',
  category: 'Docker',
  title: 'Secrets in Docker Image',
  description: 'Dockerfile may embed secrets or environment variables with sensitive data',
  detectorType: 'file',
  remediation: 'Never put secrets in Dockerfile. Use Docker secrets, environment variables at runtime, or secret management systems.',
  references: [
    {
      title: 'Docker Secrets',
      url: 'https://docs.docker.com/engine/swarm/secrets/',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.filePath.toLowerCase().includes('dockerfile')) return [];

    const { source } = context;
    const lines = source.split('\n');
    const findings: Finding[] = [];

    const secretPatterns = [
      /ENV\s+.*(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)=\S+/i,
      /ARG\s+.*(?:PASSWORD|SECRET|API_KEY|TOKEN)=\S+/i,
    ];

    lines.forEach((line, idx) => {
      for (const pattern of secretPatterns) {
        if (pattern.test(line)) {
          findings.push({
            ruleId: 'DOCKER004',
            severity: 'critical',
            category: 'Docker',
            title: 'Secrets in Dockerfile',
            description: 'Environment variable with sensitive name found in Dockerfile',
            impact: 'Secrets embedded in Docker images can be extracted from image layers.',
            remediation: 'Pass secrets at runtime via environment variables or Docker secrets',
            references: dockerSecretsInImageRule.references,
            filePath: context.filePath,
            line: idx + 1,
          });
        }
      }
    });

    return findings;
  },
};

export const dockerCopyDotRule: Rule = {
  id: 'DOCKER005',
  severity: 'low',
  category: 'Docker',
  title: 'COPY . . in Dockerfile',
  description: 'Dockerfile uses COPY . . which may include unnecessary files and bloat the image',
  detectorType: 'file',
  remediation: 'Copy only necessary files or use .dockerignore',
  references: [
    {
      title: 'Dockerfile Best Practices',
      url: 'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!context.filePath.toLowerCase().includes('dockerfile')) return [];

    const { source } = context;
    const lines = source.split('\n');
    const findings: Finding[] = [];

    lines.forEach((line, idx) => {
      if (/^COPY\s+\.\s+\./i.test(line)) {
        findings.push({
          ruleId: 'DOCKER005',
          severity: 'low',
          category: 'Docker',
          title: 'COPY . . in Dockerfile',
          description: 'COPY . . copies entire context, which may include unnecessary files',
          impact: 'Including unnecessary files (node_modules, .git, etc.) increases image size and build time.',
          remediation: 'Use .dockerignore or copy specific files: COPY package*.json ./ && COPY src ./src',
          references: dockerCopyDotRule.references,
          filePath: context.filePath,
          line: idx + 1,
        });
      }
    });

    return findings;
  },
};
