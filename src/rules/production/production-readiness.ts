import type { Rule, RuleContext, Finding } from '../../types/index.js';
import type { File } from '@babel/types';
import { traverse, getNodeLine, findImports } from '../../core/ast-helpers.js';
import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';
import { isEntryFile } from '../../core/is-entry-file.js';
import { bothStyles } from '../../core/remediation.js';

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
      title: 'Express Best Practices - Health Checks',
      url: 'https://expressjs.com/en/advanced/healthcheck-graceful-shutdown.html',
    },
    {
      title: 'Kubernetes Health Checks',
      url: 'https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/',
    },
  ],

  run(context: RuleContext): Finding[] {
    if (!isEntryFile(context.filePath, context.projectRoot, context.source)) return [];
    if (!context.ast) return [];

    const { source } = context;
    const hasHealth =
      source.includes('/health') ||
      source.includes('/healthz') ||
      source.includes('/ping') ||
      source.includes('/status');

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

    const { source } = context;
    const hasGracefulShutdown =
      source.includes('SIGTERM') ||
      source.includes('SIGINT') ||
      source.includes('server.close');

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

    const ast = context.ast as File;
    let hasTrustProxy = false;

    traverse(ast, {
      CallExpression(path: NodePath<BabelTypes.CallExpression>) {
        const callee = path.node.callee;
        if (
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          callee.property.name === 'set'
        ) {
          const firstArg = path.node.arguments[0];
          if (
            firstArg?.type === 'StringLiteral' &&
            firstArg.value === 'trust proxy'
          ) {
            hasTrustProxy = true;
          }
        }
      },
    });

    if (!hasTrustProxy) {
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
    }

    return [];
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

    const ast = context.ast as File;
    const hasCompression =
      findImports(ast, 'compression') ||
      findImports(ast, '@fastify/compress') ||
      findImports(ast, 'shrink-ray-current');

    if (!hasCompression) {
      return [{
        ruleId: 'PROD004',
        severity: 'low',
        category: 'Production Readiness',
        title: 'Compression Middleware Missing',
        description: 'No compression middleware detected in app entry',
        impact: 'Without compression, response payloads are larger, increasing bandwidth costs and latency.',
        remediation: compressionMissingRule.remediation,
        references: compressionMissingRule.references,
        filePath: context.filePath,
      }];
    }

    return [];
  },
};
