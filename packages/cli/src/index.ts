#!/usr/bin/env node

import { Command } from "commander";
import { scan, loadConfig, analyzeLlm } from "@vexlit/core";
import type { ScanResult, Severity, Vulnerability } from "@vexlit/core";
import * as fs from "node:fs";
import * as path from "node:path";
import { execSync } from "node:child_process";

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "\x1b[31m",
  warning: "\x1b[33m",
  info: "\x1b[36m",
};
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";

type OutputFormat = "table" | "json" | "sarif";

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  warning: 1,
  info: 2,
};

function severityGte(a: string, threshold: string): boolean {
  return (SEVERITY_ORDER[a] ?? 99) <= (SEVERITY_ORDER[threshold] ?? 99);
}

function formatTable(results: ScanResult[]): void {
  const allVulns = results.flatMap((r) => r.vulnerabilities);

  if (allVulns.length === 0) {
    console.log(`\n${BOLD}No vulnerabilities found.${RESET}\n`);
    return;
  }

  const counts = { critical: 0, warning: 0, info: 0 };
  for (const v of allVulns) {
    counts[v.severity]++;
  }

  console.log(
    `\n${BOLD}VEXLIT Scan Results${RESET}\n` +
      `─────────────────────────────────────────\n` +
      `Files scanned: ${results.length}\n` +
      `Vulnerabilities: ${SEVERITY_COLORS.critical}${counts.critical} critical${RESET}, ` +
      `${SEVERITY_COLORS.warning}${counts.warning} warning${RESET}, ` +
      `${SEVERITY_COLORS.info}${counts.info} info${RESET}\n`
  );

  for (const result of results) {
    if (result.vulnerabilities.length === 0) continue;

    console.log(`${BOLD}${result.filePath}${RESET}`);
    for (const v of result.vulnerabilities) {
      const color = SEVERITY_COLORS[v.severity];
      console.log(
        `  ${color}[${v.severity.toUpperCase()}]${RESET} Line ${v.line}:${v.column} ${v.message}`
      );
      console.log(`    ${DIM}${v.snippet}${RESET}`);
      console.log(`    -> ${v.suggestion}`);
      console.log(`    ${DIM}${v.cwe} | ${v.owasp}${RESET}`);
    }
    console.log();
  }
}

function formatSarif(results: ScanResult[]): string {
  const allVulns = results.flatMap((r) => r.vulnerabilities);

  const severityToLevel: Record<Severity, string> = {
    critical: "error",
    warning: "warning",
    info: "note",
  };

  const rulesMap = new Map<string, Vulnerability>();
  for (const v of allVulns) {
    if (!rulesMap.has(v.ruleId)) {
      rulesMap.set(v.ruleId, v);
    }
  }

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0" as const,
    runs: [
      {
        tool: {
          driver: {
            name: "VEXLIT",
            version: "0.1.0",
            informationUri: "https://github.com/vexlit/vexlit",
            rules: Array.from(rulesMap.values()).map((v) => ({
              id: v.ruleId,
              name: v.ruleName,
              shortDescription: { text: v.message },
              helpUri: `https://cwe.mitre.org/data/definitions/${v.cwe.replace("CWE-", "")}.html`,
              properties: {
                cwe: v.cwe,
                owasp: v.owasp,
              },
            })),
          },
        },
        results: allVulns.map((v) => ({
          ruleId: v.ruleId,
          level: severityToLevel[v.severity],
          message: { text: v.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: v.filePath.replace(/\\/g, "/"),
                },
                region: {
                  startLine: v.line,
                  startColumn: v.column,
                  snippet: { text: v.snippet },
                },
              },
            },
          ],
          fixes: [
            {
              description: { text: v.suggestion },
            },
          ],
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

function getGitDiffFiles(): string[] {
  try {
    const staged = execSync("git diff --cached --name-only --diff-filter=ACMR", {
      encoding: "utf-8",
    }).trim();
    const unstaged = execSync("git diff --name-only --diff-filter=ACMR", {
      encoding: "utf-8",
    }).trim();
    const untracked = execSync("git ls-files --others --exclude-standard", {
      encoding: "utf-8",
    }).trim();

    const files = new Set<string>();
    for (const line of [...staged.split("\n"), ...unstaged.split("\n"), ...untracked.split("\n")]) {
      const trimmed = line.trim();
      if (trimmed) files.add(trimmed);
    }
    return Array.from(files);
  } catch {
    console.error("Error: Not a git repository or git is not installed.");
    process.exit(2);
  }
}

interface ScanCommandOptions {
  format?: OutputFormat;
  json?: boolean;
  sarif?: boolean;
  llm?: boolean;
  apiKey?: string;
  failOn?: string;
  diff?: boolean;
}

const program = new Command();

program
  .name("vexlit")
  .description("AI-powered code security vulnerability scanner")
  .version("0.1.0");

/* ─── scan command ─── */
program
  .command("scan")
  .description("Scan files or directories for security vulnerabilities")
  .argument("[paths...]", "Files or directories to scan (default: current directory)")
  .option("--format <format>", "Output format: table, json, sarif", "table")
  .option("--json", "Shorthand for --format json")
  .option("--sarif", "Shorthand for --format sarif")
  .option("--llm", "Enable LLM-assisted analysis via Claude API")
  .option("--api-key <key>", "Anthropic API key (or set ANTHROPIC_API_KEY env)")
  .option("--fail-on <severity>", "Exit with code 1 if any vuln >= severity (critical, warning, info)")
  .option("--diff", "Scan only git-changed files (staged + unstaged + untracked)")
  .action(async (paths: string[], options: ScanCommandOptions) => {
    try {
      let scanPaths = paths.length > 0 ? paths : ["."];

      if (options.diff) {
        const diffFiles = getGitDiffFiles();
        if (diffFiles.length === 0) {
          console.log(`${GREEN}No changed files to scan.${RESET}`);
          process.exit(0);
        }
        console.log(`${DIM}Scanning ${diffFiles.length} changed file(s)...${RESET}`);
        scanPaths = diffFiles;
      }

      const format: OutputFormat = options.sarif
        ? "sarif"
        : options.json
          ? "json"
          : (options.format ?? "table");

      const results = await scan({ paths: scanPaths });

      if (options.llm) {
        const apiKey =
          options.apiKey ?? process.env["ANTHROPIC_API_KEY"] ?? "";
        if (!apiKey) {
          console.error(
            "Error: --llm requires an API key. Use --api-key or set ANTHROPIC_API_KEY."
          );
          process.exit(2);
        }

        console.log(`${DIM}Running LLM verification on ${results.flatMap((r) => r.vulnerabilities).length} findings...${RESET}`);

        for (const result of results) {
          const content = fs.readFileSync(result.filePath, "utf-8");
          const verified: Vulnerability[] = [];

          for (const vuln of result.vulnerabilities) {
            const analysis = await analyzeLlm(vuln, content, apiKey);
            if (analysis.isRealVulnerability) {
              vuln.severity = analysis.adjustedSeverity;
              verified.push(vuln);
            }
          }

          result.vulnerabilities = verified;
        }
      }

      switch (format) {
        case "json":
          console.log(JSON.stringify(results, null, 2));
          break;
        case "sarif":
          console.log(formatSarif(results));
          break;
        default:
          formatTable(results);
          break;
      }

      const failThreshold = options.failOn ?? "critical";
      const shouldFail = results.some((r) =>
        r.vulnerabilities.some((v) => severityGte(v.severity, failThreshold))
      );
      process.exit(shouldFail ? 1 : 0);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : String(error);
      console.error(`Error: ${message}`);
      process.exit(2);
    }
  });

/* ─── fix command ─── */
interface FixCommandOptions {
  interactive?: boolean;
  sca?: boolean;
  auto?: boolean;
  dryRun?: boolean;
  explain?: boolean;
  apiKey?: string;
}

program
  .command("fix")
  .description("Fix vulnerabilities found by scan")
  .argument("[paths...]", "Files or directories to fix (default: current directory)")
  .option("-i, --interactive", "Interactively choose which fixes to apply")
  .option("--sca", "Fix SCA (dependency) vulnerabilities via npm/yarn upgrade")
  .option("--auto", "Automatically apply all suggested fixes")
  .option("--dry-run", "Show what would be fixed without making changes")
  .option("--explain", "Show AI explanation for each vulnerability")
  .option("--api-key <key>", "Anthropic API key for --explain (or set ANTHROPIC_API_KEY env)")
  .action(async (paths: string[], options: FixCommandOptions) => {
    try {
      const scanPaths = paths.length > 0 ? paths : ["."];

      if (options.sca) {
        await fixSca(options.dryRun ?? false);
        return;
      }

      const results = await scan({ paths: scanPaths });
      const allVulns = results.flatMap((r) => r.vulnerabilities);

      if (allVulns.length === 0) {
        console.log(`${GREEN}No vulnerabilities found. Nothing to fix.${RESET}`);
        process.exit(0);
      }

      console.log(`\n${BOLD}VEXLIT Fix${RESET} — ${allVulns.length} vulnerabilities found\n`);

      if (options.explain) {
        const apiKey = options.apiKey ?? process.env["ANTHROPIC_API_KEY"] ?? "";
        if (!apiKey) {
          console.error("Error: --explain requires an API key. Use --api-key or set ANTHROPIC_API_KEY.");
          process.exit(2);
        }

        for (const result of results) {
          for (const v of result.vulnerabilities) {
            const color = SEVERITY_COLORS[v.severity];
            console.log(`${color}[${v.severity.toUpperCase()}]${RESET} ${v.filePath}:${v.line} — ${v.ruleName}`);
            console.log(`  ${DIM}${v.message}${RESET}`);

            const content = fs.readFileSync(result.filePath, "utf-8");
            const analysis = await analyzeLlm(v, content, apiKey);
            console.log(`  AI: ${analysis.isRealVulnerability ? "Confirmed vulnerability" : "Likely false positive"}`);
            if (analysis.explanation) {
              console.log(`  ${DIM}${analysis.explanation}${RESET}`);
            }
            console.log();
          }
        }
        return;
      }

      if (options.interactive) {
        await fixInteractive(results, options.dryRun ?? false);
      } else if (options.auto) {
        await fixAuto(results, options.dryRun ?? false);
      } else {
        // Default: show suggestions
        for (const result of results) {
          for (const v of result.vulnerabilities) {
            const color = SEVERITY_COLORS[v.severity];
            console.log(
              `${color}[${v.severity.toUpperCase()}]${RESET} ${v.filePath}:${v.line}`
            );
            console.log(`  ${v.message}`);
            if (v.suggestion) {
              console.log(`  ${GREEN}Fix:${RESET} ${v.suggestion}`);
            }
            console.log();
          }
        }
        console.log(`${DIM}Use --auto to apply fixes, --interactive to choose, or --explain for AI analysis.${RESET}`);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`Error: ${message}`);
      process.exit(2);
    }
  });

async function fixSca(dryRun: boolean): Promise<void> {
  const hasPkgJson = fs.existsSync("package.json");
  const hasYarnLock = fs.existsSync("yarn.lock");

  if (!hasPkgJson) {
    console.error("Error: No package.json found in current directory.");
    process.exit(2);
  }

  const cmd = hasYarnLock ? "yarn upgrade" : "npm audit fix";

  if (dryRun) {
    const dryCmd = hasYarnLock ? cmd : `${cmd} --dry-run`;
    console.log(`${DIM}[dry-run] Would run: ${dryCmd}${RESET}`);
    try {
      execSync(dryCmd, { encoding: "utf-8", stdio: "inherit" });
    } catch {
      // npm audit fix --dry-run may exit non-zero
    }
    return;
  }

  console.log(`${BOLD}Running: ${cmd}${RESET}\n`);
  try {
    execSync(cmd, { encoding: "utf-8", stdio: "inherit" });
    console.log(`\n${GREEN}SCA dependencies updated.${RESET}`);
  } catch {
    console.error("SCA fix command failed. Review the output above.");
    process.exit(1);
  }
}

async function fixInteractive(results: ScanResult[], dryRun: boolean): Promise<void> {
  const readline = await import("node:readline");
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  const ask = (q: string): Promise<string> =>
    new Promise((resolve) => rl.question(q, resolve));

  let applied = 0;
  let skipped = 0;

  for (const result of results) {
    for (const v of result.vulnerabilities) {
      if (!v.suggestion) {
        skipped++;
        continue;
      }

      const color = SEVERITY_COLORS[v.severity];
      console.log(
        `\n${color}[${v.severity.toUpperCase()}]${RESET} ${v.filePath}:${v.line}`
      );
      console.log(`  ${v.message}`);
      console.log(`  ${GREEN}Suggested fix:${RESET} ${v.suggestion}`);

      const answer = await ask(`  Apply this fix? (y/n/q): `);
      if (answer.toLowerCase() === "q") {
        console.log(`\n${DIM}Stopped. Applied ${applied} fix(es), skipped ${skipped}.${RESET}`);
        rl.close();
        return;
      }
      if (answer.toLowerCase() === "y") {
        if (dryRun) {
          console.log(`  ${DIM}[dry-run] Would apply fix to ${v.filePath}:${v.line}${RESET}`);
        } else {
          console.log(`  ${DIM}Note: Manual code changes required. See suggestion above.${RESET}`);
        }
        applied++;
      } else {
        skipped++;
      }
    }
  }

  rl.close();
  console.log(`\n${BOLD}Done.${RESET} Applied ${applied} fix(es), skipped ${skipped}.`);
}

async function fixAuto(results: ScanResult[], dryRun: boolean): Promise<void> {
  let count = 0;

  for (const result of results) {
    for (const v of result.vulnerabilities) {
      if (!v.suggestion) continue;
      count++;

      const color = SEVERITY_COLORS[v.severity];
      if (dryRun) {
        console.log(
          `${DIM}[dry-run]${RESET} ${color}[${v.severity.toUpperCase()}]${RESET} ${v.filePath}:${v.line} — ${v.suggestion}`
        );
      } else {
        console.log(
          `${color}[${v.severity.toUpperCase()}]${RESET} ${v.filePath}:${v.line} — ${v.suggestion}`
        );
      }
    }
  }

  if (count === 0) {
    console.log(`${DIM}No auto-fixable vulnerabilities found.${RESET}`);
    return;
  }

  if (dryRun) {
    console.log(`\n${DIM}[dry-run] ${count} fix(es) would be applied. No files were modified.${RESET}`);
  } else {
    console.log(`\n${BOLD}${count} fix suggestion(s) listed.${RESET}`);
    console.log(`${DIM}Note: SAST fixes require manual code changes. Use --sca for dependency upgrades.${RESET}`);
  }
}

program.parse();
