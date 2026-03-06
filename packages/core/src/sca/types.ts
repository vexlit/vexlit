/** A dependency extracted from a manifest file */
export interface Dependency {
  name: string;
  version: string;
  /** npm, PyPI, etc. */
  ecosystem: "npm" | "PyPI";
  /** The file this dependency was found in */
  source: string;
  /** Line number in the manifest file (1-indexed) */
  line: number;
  /** Whether this is a dev dependency */
  dev: boolean;
}

/** A known vulnerability from the OSV database */
export interface Advisory {
  id: string;
  summary: string;
  details: string;
  severity: "critical" | "warning" | "info";
  aliases: string[];
  /** CVSS score if available (0-10) */
  cvssScore: number | null;
  /** Affected version ranges */
  affected: string[];
  /** Fixed version if available */
  fixedVersion: string | null;
  /** Reference URLs */
  references: string[];
}

/** SCA scan result for a single dependency */
export interface ScaDependencyResult {
  dependency: Dependency;
  advisories: Advisory[];
}
