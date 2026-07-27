#!/usr/bin/env node

import { program } from 'commander';
import { resolve } from 'path';
import { writeFileSync } from 'fs';
import { AuditEngine } from './core/engine.js';
import { allRules } from './rules/index.js';
import { loadConfig, mergeConfig } from './core/config-loader.js';
import {
  generateCLIReport,
  generateJSONReport,
  generateHTMLReport,
  generateSARIFReport,
} from './reporters/index.js';

program
  .name('express-audit')
  .description('Deterministic security and production readiness auditor for Express.js applications')
  .version('1.0.0')
  .argument('[directory]', 'Project directory to audit', '.')
  .option('--json', 'Output results as JSON')
  .option('--html', 'Output results as HTML')
  .option('--sarif', 'Output results as SARIF (for GitHub Code Scanning)')
  .option('--output <file>', 'Write output to file instead of stdout')
  .option('--no-color', 'Disable colored output')
  .option('--min-severity <level>', 'Minimum severity to report (critical|high|medium|low|info)', 'info')
  .option('--disable-rules <rules>', 'Comma-separated list of rule IDs to disable')
  .option('--ignore-paths <paths>', 'Comma-separated glob patterns to ignore')
  .option('--fail-on <level>', 'Exit with code 1 if findings at this severity or above exist (critical|high|medium|low)')
  .action(async (directory: string, options: {
    json?: boolean;
    html?: boolean;
    sarif?: boolean;
    output?: string;
    color?: boolean;
    minSeverity?: string;
    disableRules?: string;
    ignorePaths?: string;
    failOn?: string;
  }) => {
    const projectRoot = resolve(directory);

    // Load file-based config, then apply CLI overrides on top
    const fileConfig = await loadConfig(projectRoot);
    const cliConfig = {
      rules: {
        disabled: options.disableRules?.split(',').map((r: string) => r.trim()) ?? [],
      },
      ignore: {
        paths: options.ignorePaths?.split(',').map((p: string) => p.trim()) ?? [],
      },
    };
    const config = mergeConfig(fileConfig, cliConfig);

    // Print starting message to stderr so it doesn't pollute --json / --sarif output
    if (!options.json && !options.sarif) {
      process.stderr.write(`\nRunning express-audit on ${projectRoot}...\n`);
    }

    try {
      const engine = new AuditEngine(config);
      engine.registerRules(allRules);
      const result = await engine.audit(projectRoot);

      // Filter by min severity if needed
      const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];
      const minSeverityIndex = severityOrder.indexOf(options.minSeverity || 'info');
      if (minSeverityIndex > 0) {
        result.findings = result.findings.filter(
          f => severityOrder.indexOf(f.severity) >= minSeverityIndex
        );
      }

      // Generate report
      let output: string;

      if (options.json) {
        output = generateJSONReport(result);
      } else if (options.html) {
        output = generateHTMLReport(result);
      } else if (options.sarif) {
        output = generateSARIFReport(result);
      } else {
        output = generateCLIReport(result);
      }

      // Write or print output
      if (options.output) {
        writeFileSync(options.output, output, 'utf-8');
        console.error(`Report written to ${options.output}`);
      } else {
        process.stdout.write(output + '\n');
      }

      // Handle exit code for CI
      if (options.failOn) {
        const failSeverityIndex = severityOrder.indexOf(options.failOn);
        const hasCriticalFindings = result.findings.some(
          f => severityOrder.indexOf(f.severity) >= failSeverityIndex
        );
        if (hasCriticalFindings) {
          process.exit(1);
        }
      }

    } catch (error) {
      console.error('Error running audit:', error);
      process.exit(2);
    }
  });

program.parse(process.argv);
