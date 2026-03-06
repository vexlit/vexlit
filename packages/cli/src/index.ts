#!/usr/bin/env node

import { Command } from "commander";
import { scan, loadConfig, analyzeLlm } from "@vexlit/core";
import type { ScanResult, Severity, Vulnerability } from "@vexlit/core";
import * as fs from "node:fs";
import * as path from "node:path";

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "\x1b[31m",
  warning: "\x1b[33m",
  info: "\x1b[36m",
};
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";

type OutputFormat = "table" | "json" | "sarif";

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

interface ScanCommandOptions {
  format?: OutputFormat;
  json?: boolean;
  sarif?: boolean;
  llm?: boolean;
  apiKey?: string;
}

const program = new Command();

program
  .name("vexlit")
  .description("AI-powered code security vulnerability scanner")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan files or directories for security vulnerabilities")
  .argument("<paths...>", "Files or directories to scan")
  .option("--format <format>", "Output format: table, json, sarif", "table")
  .option("--json", "Shorthand for --format json")
  .option("--sarif", "Shorthand for --format sarif")
  .option("--llm", "Enable LLM-assisted analysis via Claude API")
  .option("--api-key <key>", "Anthropic API key (or set ANTHROPIC_API_KEY env)")
  .action(async (paths: string[], options: ScanCommandOptions) => {
    try {
      const format: OutputFormat = options.sarif
        ? "sarif"
        : options.json
          ? "json"
          : (options.format ?? "table");

      const results = await scan({ paths });

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

      const hasCritical = results.some((r) =>
        r.vulnerabilities.some((v) => v.severity === "critical")
      );
      process.exit(hasCritical ? 1 : 0);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : String(error);
      console.error(`Error: ${message}`);
      process.exit(2);
    }
  });

program.parse();
