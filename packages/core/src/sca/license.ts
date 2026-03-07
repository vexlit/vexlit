import type { Vulnerability } from "../types.js";
import type { Dependency } from "./types.js";

/** Copyleft license families — strong copyleft triggers critical */
const STRONG_COPYLEFT = new Set([
  "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
  "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
  "AGPL-1.0", "AGPL-1.0-only", "AGPL-1.0-or-later",
  "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
  "SSPL-1.0",
  "EUPL-1.1", "EUPL-1.2",
]);

/** Weak copyleft — triggers warning */
const WEAK_COPYLEFT = new Set([
  "LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
  "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
  "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
  "MPL-2.0",
  "EPL-1.0", "EPL-2.0",
  "OSL-3.0",
  "CPAL-1.0",
]);

export type LicenseRisk = "critical" | "warning" | "none";

/** Classify a single SPDX license identifier */
export function classifyLicense(spdxId: string): LicenseRisk {
  const id = spdxId.trim();
  if (STRONG_COPYLEFT.has(id)) return "critical";
  if (WEAK_COPYLEFT.has(id)) return "warning";
  return "none";
}

/**
 * Analyze dependencies for copyleft license risks.
 * Returns Vulnerability[] entries for flagged licenses.
 */
export function analyzeLicenses(deps: Dependency[]): Vulnerability[] {
  const vulns: Vulnerability[] = [];

  for (const dep of deps) {
    if (!dep.license) continue;

    // Handle SPDX expressions like "MIT OR GPL-3.0"
    const parts = dep.license.split(/\s+OR\s+|\s+AND\s+|\s*\(\s*|\s*\)\s*/i).filter(Boolean);
    let worstRisk: LicenseRisk = "none";
    for (const part of parts) {
      const risk = classifyLicense(part);
      if (risk === "critical") { worstRisk = "critical"; break; }
      if (risk === "warning") worstRisk = "warning";
    }

    if (worstRisk === "none") continue;

    const devLabel = dep.dev ? " (dev)" : "";
    vulns.push({
      ruleId: `LICENSE-${worstRisk === "critical" ? "COPYLEFT" : "WEAK-COPYLEFT"}`,
      ruleName: `Copyleft license: ${dep.name}${devLabel}`,
      severity: worstRisk,
      confidence: "high",
      message: `${dep.name}@${dep.version}${devLabel} uses ${dep.license}, which is a ${worstRisk === "critical" ? "strong" : "weak"} copyleft license. This may require you to release your source code under the same license.`,
      filePath: dep.source,
      line: dep.line,
      column: 1,
      snippet: `[${dep.ecosystem}] "${dep.name}": "${dep.version}" — License: ${dep.license}`,
      cwe: "",
      owasp: "",
      suggestion: worstRisk === "critical"
        ? `Consider replacing ${dep.name} with an MIT/Apache-2.0 licensed alternative to avoid copyleft obligations.`
        : `Review ${dep.license} terms. Weak copyleft (LGPL/MPL) may allow use in proprietary software under certain conditions.`,
    });
  }

  return vulns;
}
