import type { Severity } from "../types.js";
import type { Policy, PolicyEvaluation, VulnForPolicy } from "./types.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  warning: 1,
  critical: 2,
};

/**
 * Evaluate a set of policies against scan vulnerabilities.
 * Returns an evaluation result for each enabled policy.
 */
export function evaluatePolicies(
  policies: Policy[],
  vulns: VulnForPolicy[]
): PolicyEvaluation[] {
  return policies
    .filter((p) => p.enabled)
    .map((policy) => evaluatePolicy(policy, vulns));
}

function evaluatePolicy(
  policy: Policy,
  vulns: VulnForPolicy[]
): PolicyEvaluation {
  const matchedIndices: number[] = [];
  const { conditions } = policy;

  for (let i = 0; i < vulns.length; i++) {
    if (matchesConditions(vulns[i], conditions)) {
      matchedIndices.push(i);
    }
  }

  const violated =
    policy.action === "ignore"
      ? false // "ignore" policies never fail — they suppress
      : matchedIndices.length > 0;

  return {
    policyId: policy.id,
    policyName: policy.name,
    action: policy.action,
    status: violated ? "violated" : "passed",
    matchedCount: matchedIndices.length,
    matchedIndices,
  };
}

function matchesConditions(
  vuln: VulnForPolicy,
  cond: Policy["conditions"]
): boolean {
  // Severity threshold
  if (cond.severity_gte) {
    if (SEVERITY_ORDER[vuln.severity] < SEVERITY_ORDER[cond.severity_gte]) {
      return false;
    }
  }

  // Reachability filter
  if (cond.reachable_only && vuln.reachable !== true) {
    return false;
  }

  // Source filter (SAST vs SCA vs license)
  if (cond.source) {
    const isSca = vuln.ruleId.startsWith("SCA-");
    const isLicense = vuln.ruleId.startsWith("LICENSE-");
    if (cond.source === "sast" && (isSca || isLicense)) return false;
    if (cond.source === "sca" && !isSca) return false;
    if (cond.source === "license" && !isLicense) return false;
  }

  // CWE filter
  if (cond.cwe_ids?.length) {
    if (!cond.cwe_ids.includes(vuln.cwe)) return false;
  }

  // Package pattern filter (for SCA)
  if (cond.package_patterns?.length) {
    if (!vuln.packageName) return false;
    const matched = cond.package_patterns.some((pattern) =>
      matchGlob(vuln.packageName!, pattern)
    );
    if (!matched) return false;
  }

  // Dev deps filter
  if (cond.include_dev_deps === false && vuln.isDev) {
    return false;
  }

  // License type filter
  if (cond.license_types?.length) {
    const isStrongCopyleft = vuln.ruleId === "LICENSE-COPYLEFT";
    const isWeakCopyleft = vuln.ruleId === "LICENSE-WEAK-COPYLEFT";
    const matched = cond.license_types.some(
      (lt) =>
        (lt === "strong-copyleft" && isStrongCopyleft) ||
        (lt === "weak-copyleft" && isWeakCopyleft)
    );
    if (!matched) return false;
  }

  return true;
}

/** Simple glob matching — supports * wildcard */
function matchGlob(value: string, pattern: string): boolean {
  const regex = new RegExp(
    "^" + pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\\*/g, ".*") + "$"
  );
  return regex.test(value);
}
