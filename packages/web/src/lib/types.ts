export interface Profile {
  id: string;
  terms_version: string | null;
  terms_accepted_at: string | null;
  terms_ip: string | null;
  marketing_consent: boolean;
  repo_scope: "public_only" | "all";
  feature_pr_check: boolean;
  feature_auto_fix_pr: boolean;
  feature_dep_upgrade: boolean;
  feature_code_analysis: boolean;
  created_at: string;
  updated_at: string;
}

export interface Notification {
  id: string;
  user_id: string;
  type: string;
  title: string;
  message: string | null;
  link: string | null;
  read_at: string | null;
  created_at: string;
}

export interface Project {
  id: string;
  user_id: string;
  name: string;
  github_url: string | null;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  project_id: string;
  status: "pending" | "running" | "completed" | "failed";
  commit_sha: string | null;
  branch: string | null;
  total_vulnerabilities: number;
  critical_count: number;
  warning_count: number;
  info_count: number;
  duration_ms: number | null;
  sarif_json: unknown | null;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface Vulnerability {
  id: string;
  scan_id: string;
  rule_id: string;
  rule_name: string;
  severity: "critical" | "warning" | "info";
  message: string;
  file_path: string;
  line: number;
  column: number;
  snippet: string | null;
  cwe: string | null;
  owasp: string | null;
  suggestion: string | null;
  confidence: "high" | "medium" | "low";
  created_at: string;
}

export interface ScanWithProject extends Scan {
  projects: Pick<Project, "name">;
}
