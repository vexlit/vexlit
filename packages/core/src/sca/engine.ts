import type { Vulnerability } from "../types.js";
import type { Dependency } from "./types.js";
import { parseDependencies, isDependencyFile } from "./parser.js";
import { queryOsv } from "./osv.js";
import { analyzeLicenses } from "./license.js";

export interface ScaResult {
  vulnerabilities: Vulnerability[];
  /** All parsed dependencies (for SBOM generation) */
  dependencies: Dependency[];
  depCount: number;
  skipped: boolean;
}

/**
 * Run SCA analysis on a set of files.
 * Detects dependency manifests, parses them, queries OSV,
 * and returns vulnerabilities + metadata.
 */
export async function scaDependencies(
  files: { path: string; content: string }[]
): Promise<ScaResult> {
  // Step 1: Find and parse all dependency files
  const allDeps: Dependency[] = [];
  for (const file of files) {
    if (!isDependencyFile(file.path)) continue;
    const deps = parseDependencies(file.path, file.content);
    allDeps.push(...deps);
  }

  if (!allDeps.length) return { vulnerabilities: [], dependencies: [], depCount: 0, skipped: false };

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

  // Step 2.5: Cap at 1500 packages to protect against huge repos
  const MAX_PACKAGES = 1500;
  if (uniqueDeps.length > MAX_PACKAGES) {
    uniqueDeps.length = MAX_PACKAGES;
  }

  // Step 3: Query OSV for known vulnerabilities (deduplicated)
  let advisoryMap: Map<string, import("./types.js").Advisory[]>;
  try {
    advisoryMap = await queryOsv(uniqueDeps);
  } catch {
    // OSV unreachable after retries — skip SCA
    return { vulnerabilities: [], dependencies: uniqueDeps, depCount: uniqueDeps.length, skipped: true };
  }

  // Step 4: Convert to Vulnerability[] (report against all source files)
  const vulnerabilities: Vulnerability[] = [];

  for (const dep of allDeps) {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    const advisories = advisoryMap.get(key);
    if (!advisories?.length) continue;

    for (const adv of advisories) {
      const cveAlias = adv.aliases.find((a) => a.startsWith("CVE-")) ?? adv.id;
      const fixCmd = adv.fixedVersion
        ? buildUpgradeCommand(dep.name, adv.fixedVersion, dep.ecosystem, dep.dev)
        : null;
      const fixMsg = adv.fixedVersion
        ? ` Safe version: ${adv.fixedVersion}. ${fixCmd ?? ""}`
        : " Check the advisory for remediation steps.";

      const devLabel = dep.dev ? " (dev)" : "";
      vulnerabilities.push({
        ruleId: `SCA-${adv.id}`,
        ruleName: `Vulnerable dependency: ${dep.name}${devLabel}`,
        severity: adv.severity,
        confidence: "high",
        message: `${dep.name}@${dep.version}${devLabel} has a known vulnerability: ${adv.summary} (${cveAlias})`,
        filePath: dep.source,
        line: dep.line,
        column: 1,
        snippet: `[${dep.ecosystem}] "${dep.name}": "${dep.version}"`,
        cwe: "CWE-1395",
        owasp: "A06:2021",
        suggestion: `Upgrade ${dep.name} to a non-vulnerable version.${fixMsg}`,
      });
    }
  }

  // Step 5: Analyze licenses for copyleft risks
  const licenseVulns = analyzeLicenses(uniqueDeps);
  vulnerabilities.push(...licenseVulns);

  return { vulnerabilities, dependencies: uniqueDeps, depCount: uniqueDeps.length, skipped: false };
}

/** Build a package-manager-specific upgrade command */
function buildUpgradeCommand(
  name: string,
  version: string,
  ecosystem: string,
  dev: boolean
): string | null {
  switch (ecosystem) {
    case "npm": {
      const flag = dev ? " --save-dev" : "";
      return `Run: npm install ${name}@${version}${flag}`;
    }
    case "PyPI":
      return `Run: pip install ${name}==${version}`;
    case "Go":
      return `Run: go get ${name}@${version}`;
    case "crates.io":
      return `Update Cargo.toml: ${name} = "${version}"`;
    default:
      return null;
  }
}
