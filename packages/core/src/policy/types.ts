import type { Severity } from "../types.js";

/** A user-defined security policy rule */
export interface Policy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  /** Conditions that trigger this policy */
  conditions: PolicyConditions;
  /** Action to take when conditions match */
  action: "block" | "warn" | "ignore";
}

export interface PolicyConditions {
  /** Minimum severity to match (e.g., "critical" matches critical only, "warning" matches warning+critical) */
  severity_gte?: Severity;
  /** Only match reachable vulnerabilities */
  reachable_only?: boolean;
  /** Match specific vulnerability source */
  source?: "sast" | "sca" | "license";
  /** Match specific CWE IDs (e.g., ["CWE-89", "CWE-79"]) */
  cwe_ids?: string[];
  /** Match package name patterns (glob-like, for SCA) */
  package_patterns?: string[];
  /** Include/exclude dev dependencies */
  include_dev_deps?: boolean;
  /** Match specific license types */
  license_types?: ("strong-copyleft" | "weak-copyleft")[];
}

/** Result of evaluating a single policy against a scan */
export interface PolicyEvaluation {
  policyId: string;
  policyName: string;
  action: "block" | "warn" | "ignore";
  status: "passed" | "violated";
  /** Number of vulnerabilities matching the policy conditions */
  matchedCount: number;
  /** Matched vulnerability indices (into the input array) */
  matchedIndices: number[];
}

/** Vulnerability metadata for policy evaluation */
export interface VulnForPolicy {
  ruleId: string;
  severity: Severity;
  cwe: string;
  /** Package name (for SCA vulns) */
  packageName?: string;
  /** Whether this is a dev dependency */
  isDev?: boolean;
  /** Whether this vulnerability is reachable from code imports */
  reachable?: boolean;
}
