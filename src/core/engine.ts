import { glob } from 'glob';
import { resolve, relative } from 'path';
import type { Rule, RuleContext, Finding, AuditResult, AuditConfig, CategoryScore, Severity } from '../types/index.js';
import { parseFile } from '../parser/index.js';
import { SEVERITY_WEIGHTS, CATEGORY_WEIGHTS } from '../types/index.js';
import { VERSION as TOOL_VERSION } from '../version.js';

export class AuditEngine {
  private rules: Rule[] = [];
  private config: AuditConfig;

  constructor(config: AuditConfig = {}) {
    this.config = config;
  }

  /**
   * Register a rule for auditing
   */
  registerRule(rule: Rule): void {
    // Check if rule is disabled in config
    if (this.config.rules?.disabled?.includes(rule.id)) {
      return;
    }
    this.rules.push(rule);
  }

  /**
   * Register multiple rules at once
   */
  registerRules(rules: Rule[]): void {
    rules.forEach(rule => this.registerRule(rule));
  }

  /**
   * Run audit on a project directory
   */
  async audit(projectRoot: string): Promise<AuditResult> {
    const startTime = Date.now();
    const resolvedRoot = resolve(projectRoot);

    // Find all JavaScript/TypeScript files
    const filePatterns = [
      '**/*.js',
      '**/*.jsx',
      '**/*.ts',
      '**/*.tsx',
      '**/*.mjs',
      '**/*.cjs',
    ];

    const ignorePatterns = [
      '**/node_modules/**',
      '**/dist/**',
      '**/build/**',
      '**/coverage/**',
      '**/.next/**',
      '**/.nuxt/**',
      ...(this.config.ignore?.paths || []),
    ];

    let allFiles: string[] = [];
    for (const pattern of filePatterns) {
      const files = await glob(pattern, {
        cwd: resolvedRoot,
        ignore: ignorePatterns,
        absolute: true,
        nodir: true,
      });
      allFiles = allFiles.concat(files);
    }

    // Deduplicate files
    allFiles = [...new Set(allFiles)];

    // Also scan for Docker files and config files
    const dockerFiles = await glob('**/Dockerfile*', {
      cwd: resolvedRoot,
      ignore: ignorePatterns,
      absolute: true,
      nodir: true,
    });

    const configFiles = await glob('**/{.env*,*.config.js,*.config.ts,docker-compose*.yml}', {
      cwd: resolvedRoot,
      ignore: ignorePatterns,
      absolute: true,
      nodir: true,
    });

    const allFilesToScan = [...allFiles, ...dockerFiles, ...configFiles];

    // Run all rules on all files
    const allFindings: Finding[] = [];
    let filesAnalyzed = 0;

    for (const filePath of allFilesToScan) {
      const relPath = relative(resolvedRoot, filePath);

      // Skip if file pattern is explicitly ignored
      if (this.isFileIgnored(relPath)) {
        continue;
      }

      const { ast, source } = parseFile(filePath);
      
      const context: RuleContext = {
        filePath,
        source,
        ast: ast || undefined,
        projectRoot: resolvedRoot,
        allFiles: allFilesToScan,
        config: this.config,
      };

      filesAnalyzed++;

      // Run all rules
      for (const rule of this.rules) {
        try {
          const findings = rule.run(context);
          
          // Apply severity overrides from config
          const processedFindings = findings.map(finding => {
            const override = this.config.rules?.overrides?.[finding.ruleId];
            if (override?.severity) {
              return { ...finding, severity: override.severity };
            }
            return finding;
          });

          allFindings.push(...processedFindings);
        } catch (err) {
          // Silently skip rules that error - keep audit resilient
          console.error(`Rule ${rule.id} failed on ${relPath}:`, err);
        }
      }
    }

    // Filter out ignored rules
    const filteredFindings = allFindings.filter(
      f => !this.config.ignore?.rules?.includes(f.ruleId)
    );

    // Calculate scores
    const categoryScores = this.calculateCategoryScores(filteredFindings);
    const overallScore = this.calculateOverallScore(categoryScores);

    const result: AuditResult = {
      projectRoot: resolvedRoot,
      timestamp: new Date().toISOString(),
      version: TOOL_VERSION,
      score: overallScore,
      categoryScores,
      findings: filteredFindings,
      totalFiles: allFilesToScan.length,
      filesAnalyzed,
    };

    // Add CASA note if CASA rules were checked
    const casaFindings = filteredFindings.filter(f => f.category === 'CASA Readiness');
    if (casaFindings.length > 0 || this.rules.some(r => r.category === 'CASA Readiness')) {
      result.casaNote = 
        'These are Google CASA readiness checks only. Passing these checks does not guarantee ' +
        'passing a Google CASA assessment, as organizational controls, infrastructure, ' +
        'penetration testing, and operational practices require manual review.';
    }

    const endTime = Date.now();
    console.error(`Audit completed in ${endTime - startTime}ms`);

    return result;
  }

  private isFileIgnored(relPath: string): boolean {
    const ignorePaths = this.config.ignore?.paths || [];
    return ignorePaths.some(pattern => {
      const regex = new RegExp(pattern.replace(/\*/g, '.*'));
      return regex.test(relPath);
    });
  }

  private calculateCategoryScores(findings: Finding[]): CategoryScore[] {
    const categories = new Map<string, CategoryScore>();

    // Initialize all categories with base score
    for (const category of Object.keys(CATEGORY_WEIGHTS)) {
      categories.set(category, {
        category,
        score: 100,
        total: 100,
        findings: 0,
        criticalFindings: 0,
        highFindings: 0,
      });
    }

    // Deduct points for findings
    for (const finding of findings) {
      const categoryScore = categories.get(finding.category);
      if (!categoryScore) continue;

      categoryScore.findings++;
      
      const deduction = SEVERITY_WEIGHTS[finding.severity as Severity] || 0;
      categoryScore.score = Math.max(0, categoryScore.score - deduction);

      if (finding.severity === 'critical') categoryScore.criticalFindings++;
      if (finding.severity === 'high') categoryScore.highFindings++;
    }

    return Array.from(categories.values()).sort((a, b) => a.score - b.score);
  }

  private calculateOverallScore(categoryScores: CategoryScore[]): number {
    let weightedSum = 0;
    let totalWeight = 0;

    for (const catScore of categoryScores) {
      const weight = CATEGORY_WEIGHTS[catScore.category] || 5;
      weightedSum += catScore.score * weight;
      totalWeight += weight * 100; // Each category's perfect score is 100
    }

    return totalWeight > 0 ? Math.round((weightedSum / totalWeight) * 100) : 0;
  }
}
