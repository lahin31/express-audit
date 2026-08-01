import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, findImports } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';
import { isEntryFile } from '../../core/is-entry-file.js';
import { bothStyles } from '../../core/remediation.js';
import { parseFile } from '../../parser/index.js';
import { readFileSync, existsSync } from 'fs';

/**
 * PROD001 - Missing health endpoint
 */
export const healthEndpointRule: Rule = {
  id: 'PROD001',
  severity: 'low',
  category: 'Production Readiness',
  title: 'Missing Health Check Endpoint',
  description: 'No /health or /healthz endpoint detected in the application',
  detectorType: 'ast',
  remediation: 'Add a health check endpoint: app.get("/health", (req, res) => res.json({ status: "ok" }))',
  references: [
    {
      title: 'OWASP ASVS v4.0 – V14.5: HTTP Request Header Validation',
      url: 'https://owasp.org/www-project-application-security-verification-standard/',
    },
    {
      title: 'Express Behind Proxies',
      url: 'https://expressjs.com/en/guide/behind-proxies.html',
    },
    {
      title: 'Express Health Checks and Graceful Shutdown',
      url: 'https://expressjs.com/en/advanced/healthcheck-graceful-shutdown.html',
    },
    {
      title: 'Kubernetes Liveness and Readiness Probes',
      url: 'https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!isEntryFile(context.filePath, context.projectRoot, context.source)) return [];
    if (!context.ast) return [];

    // Check the whole project — health endpoint may be in a routes file
    const allSources = [context.source, ...context.allFiles
      .filter(f => f !== context.filePath)
      .map(f => { try { return readFileSync(f, 'utf-8'); } catch { return ''; } })
    ];

    const hasHealth = allSources.some(src =>
      src.includes('/health') ||
      src.includes('/healthz') ||
      src.includes('/ping') ||
      src.includes('/status'),
    );

    if (!hasHealth) {
      return [{
        ruleId: 'PROD001',
        severity: 'low',
        category: 'Production Readiness',
        title: 'Missing Health Check Endpoint',
        description: 'No health check endpoint detected',
        impact: 'Without a health endpoint, orchestrators (Kubernetes, load balancers) cannot verify application health.',
        remediation: 'Add: app.get("/health", (req, res) => res.status(200).json({ status: "ok", uptime: process.uptime() }))',
        references: healthEndpointRule.references,
        filePath: context.filePath,
      }];
    }

    return [];
  },
};

/**
 * PROD002 - Missing graceful shutdown
 */
export const gracefulShutdownRule: Rule = {
  id: 'PROD002',
  severity: 'low',
  category: 'Production Readiness',
  title: 'Missing Graceful Shutdown',
  description: 'Application does not handle SIGTERM/SIGINT for graceful shutdown',
  detectorType: 'ast',
  remediation: 'Implement graceful shutdown by listening for SIGTERM and SIGINT signals, then closing server and connections.',
  references: [
    {
      title: 'Express Graceful Shutdown',
      url: 'https://expressjs.com/en/advanced/healthcheck-graceful-shutdown.html',
    },
    {
      title: 'Node.js Process Signals',
      url: 'https://nodejs.org/api/process.html#signal-events',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!isEntryFile(context.filePath, context.projectRoot, context.source)) return [];

    // Check the whole project — SIGTERM handler may be in a dedicated shutdown file
    const allSources = [context.source, ...context.allFiles
      .filter(f => f !== context.filePath)
      .map(f => { try { return readFileSync(f, 'utf-8'); } catch { return ''; } })
    ];

    const hasGracefulShutdown = allSources.some(src =>
      src.includes('SIGTERM') ||
      src.includes('SIGINT') ||
      src.includes('server.close'),
    );

    if (!hasGracefulShutdown) {
      return [{
        ruleId: 'PROD002',
        severity: 'low',
        category: 'Production Readiness',
        title: 'Missing Graceful Shutdown',
        description: 'No graceful shutdown handler found',
        impact: 'Without graceful shutdown, in-flight requests are dropped and database connections may not be cleanly closed.',
        remediation: `Add:
process.on('SIGTERM', () => {
  server.close(() => {
    db.disconnect();
    process.exit(0);
  });
});`,
        references: gracefulShutdownRule.references,
        filePath: context.filePath,
      }];
    }

    return [];
  },
};

/**
 * PROD003 - Missing trust proxy
 */
export const trustProxyRule: Rule = {
  id: 'PROD003',
  severity: 'medium',
  category: 'Production Readiness',
  title: 'Missing Trust Proxy Configuration',
  description: 'app.set("trust proxy") is not configured, which may cause issues with rate limiting and request IP detection behind load balancers',
  detectorType: 'ast',
  remediation: 'Configure trust proxy if behind a reverse proxy: app.set("trust proxy", 1)',
  references: [
    {
      title: 'Express Behind Proxies',
      url: 'https://expressjs.com/en/guide/behind-proxies.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!isEntryFile(context.filePath, context.projectRoot, context.source)) return [];
    if (!context.ast) return [];

    // Check entry file and all other project files
    const filesToCheck = [
      { filePath: context.filePath, ast: context.ast as File },
      ...context.allFiles
        .filter(f => f !== context.filePath)
        .map(f => {
          try {
            const src = readFileSync(f, 'utf-8');
            if (!src.includes('trust proxy')) return null;
            const { ast } = parseFile(f);
            return ast ? { filePath: f, ast } : null;
          } catch { return null; }
        })
        .filter((x): x is { filePath: string; ast: File } => x !== null),
    ];

    for (const { ast } of filesToCheck) {
      let found = false;
      traverse(ast, {
        CallExpression(path: NodePath<BabelTypes.CallExpression>) {
          const callee = path.node.callee;
          if (
            callee.type === 'MemberExpression' &&
            callee.property.type === 'Identifier' &&
            callee.property.name === 'set'
          ) {
            const firstArg = path.node.arguments[0];
            if (firstArg?.type === 'StringLiteral' && firstArg.value === 'trust proxy') {
              found = true;
            }
          }
        },
      });
      if (found) return [];
    }

    return [{
      ruleId: 'PROD003',
      severity: 'medium',
      category: 'Production Readiness',
      title: 'Missing Trust Proxy Configuration',
      description: 'trust proxy not configured',
      impact: 'Without trust proxy, rate limiting and IP-based features may use incorrect IPs behind load balancers.',
      remediation: 'Add before routes: app.set("trust proxy", 1)',
      references: trustProxyRule.references,
      filePath: context.filePath,
    }];
  },
};

/**
 * PROD004 - Missing compression middleware
 */
export const compressionMissingRule: Rule = {
  id: 'PROD004',
  severity: 'low',
  category: 'Production Readiness',
  title: 'Compression Middleware Missing',
  description: 'No compression middleware detected, which impacts response performance',
  detectorType: 'ast',
  remediation: bothStyles('compression', 'compression', 'app.use(compression());'),
  references: [
    {
      title: 'Express Compression',
      url: 'https://expressjs.com/en/resources/middleware/compression.html',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!isEntryFile(context.filePath, context.projectRoot, context.source)) return [];
    if (!context.ast) return [];

    const COMPRESSION_PACKAGES = ['compression', '@fastify/compress', 'shrink-ray-current'];

    // 1. Check the entry file
    const ast = context.ast as File;
    if (COMPRESSION_PACKAGES.some(pkg => findImports(ast, pkg))) return [];

    // 2. Scan all project files — compression may be in a middleware setup file
    for (const filePath of context.allFiles) {
      if (filePath === context.filePath) continue;
      if (!existsSync(filePath)) continue;

      let src: string;
      try { src = readFileSync(filePath, 'utf-8'); } catch { continue; }
      if (!COMPRESSION_PACKAGES.some(pkg => src.includes(pkg))) continue;

      const { ast: fileAst } = parseFile(filePath);
      if (fileAst && COMPRESSION_PACKAGES.some(pkg => findImports(fileAst, pkg))) return [];
    }

    return [{
      ruleId: 'PROD004',
      severity: 'low',
      category: 'Production Readiness',
      title: 'Compression Middleware Missing',
      description: 'No compression middleware detected in the project',
      impact: 'Without compression, response payloads are larger, increasing bandwidth costs and latency.',
      remediation: compressionMissingRule.remediation,
      references: compressionMissingRule.references,
      filePath: context.filePath,
    }];
  },
};
