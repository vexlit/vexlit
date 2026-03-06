import type { Vulnerability } from "../types.js";
import type { Dependency } from "./types.js";
import { parseDependencies, isDependencyFile } from "./parser.js";
import { queryOsv } from "./osv.js";

/**
 * Run SCA analysis on a set of files.
 * Detects dependency manifests, parses them, queries OSV,
 * and returns Vulnerability[] compatible with the existing scan pipeline.
 */
export async function scaDependencies(
  files: { path: string; content: string }[]
): Promise<Vulnerability[]> {
  // Step 1: Find and parse all dependency files
  const allDeps: Dependency[] = [];
  for (const file of files) {
    if (!isDependencyFile(file.path)) continue;
    const deps = parseDependencies(file.path, file.content);
    allDeps.push(...deps);
  }

  if (!allDeps.length) return [];

  // Step 2: Deduplicate — same package may appear in multiple manifests
  const seen = new Map<string, Dependency>();
  const uniqueDeps: Dependency[] = [];
  for (const dep of allDeps) {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    if (!seen.has(key)) {
      seen.set(key, dep);
      uniqueDeps.push(dep);
    }
  }

  // Step 3: Query OSV for known vulnerabilities (deduplicated)
  const advisoryMap = await queryOsv(uniqueDeps);

  // Step 4: Convert to Vulnerability[] (report against all source files)
  const vulnerabilities: Vulnerability[] = [];

  for (const dep of allDeps) {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    const advisories = advisoryMap.get(key);
    if (!advisories?.length) continue;

    for (const adv of advisories) {
      const cveAlias = adv.aliases.find((a) => a.startsWith("CVE-")) ?? adv.id;
      const fixMsg = adv.fixedVersion
        ? ` Upgrade to ${adv.fixedVersion} or later.`
        : " Check the advisory for remediation steps.";

      vulnerabilities.push({
        ruleId: `SCA-${adv.id}`,
        ruleName: `Vulnerable dependency: ${dep.name}`,
        severity: adv.severity,
        confidence: "high",
        message: `${dep.name}@${dep.version} has a known vulnerability: ${adv.summary} (${cveAlias})`,
        filePath: dep.source,
        line: dep.line,
        column: 1,
        snippet: `"${dep.name}": "${dep.version}"`,
        cwe: "CWE-1395",
        owasp: "A06:2021",
        suggestion: `Upgrade ${dep.name} to a non-vulnerable version.${fixMsg}`,
      });
    }
  }

  return vulnerabilities;
}
