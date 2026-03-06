export type Severity = "critical" | "warning" | "info";

export type Confidence = "high" | "medium" | "low";

export type Language = "javascript" | "typescript" | "python";

export interface Vulnerability {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  confidence: Confidence;
  message: string;
  filePath: string;
  line: number;
  column: number;
  snippet: string;
  cwe: string;
  owasp: string;
  suggestion: string;
}

export interface ScanResult {
  filePath: string;
  language: Language;
  vulnerabilities: Vulnerability[];
  scannedAt: string;
}

export interface RuleConfig {
  enabled?: boolean;
  severity?: Severity;
}

export interface VexlitConfig {
  rules?: Record<string, RuleConfig | false>;
  ignore?: string[];
  languages?: Language[];
  enableLlm?: boolean;
  anthropicApiKey?: string;
}

export interface ScanOptions {
  paths: string[];
  config?: VexlitConfig;
}

export interface ScanContext {
  filePath: string;
  content: string;
  lines: string[];
  language: Language;
  ast: unknown | null;
}

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  cwe: string;
  owasp: string;
  languages: Language[];
  suggestion: string;
  scan(ctx: ScanContext): Vulnerability[];
}
