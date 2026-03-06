import type { Rule, Vulnerability, ScanContext } from "../types.js";
import { allSecretPatterns } from "./patterns.js";

const SAFE_ENV_PATTERNS =
  /process\.env|os\.environ|import\.meta\.env|System\.getenv|getenv|dotenv/;

export const secretPatternRules: Rule[] = allSecretPatterns.map((sp) => ({
  id: `VEXLIT-SEC-${sp.id}`,
  name: sp.name,
  severity: sp.severity,
  description: `${sp.name} detected in source code`,
  cwe: sp.cwe,
  owasp: sp.owasp,
  languages: ["javascript", "typescript", "python"] as const,
  suggestion: "Move secrets to environment variables or a secrets manager",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulns: Vulnerability[] = [];

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];

      // Regex prefilter
      if (!sp.pattern.test(line)) continue;

      // Skip env references (safe assignments)
      if (SAFE_ENV_PATTERNS.test(line)) continue;

      // Skip comments
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

      vulns.push({
        ruleId: this.id,
        ruleName: this.name,
        severity: this.severity,
        message: `${sp.name} found in source code`,
        filePath: ctx.filePath,
        line: i + 1,
        column: line.search(sp.pattern) + 1,
        snippet: line.trim(),
        cwe: sp.cwe,
        owasp: sp.owasp,
        suggestion: this.suggestion,
      });
    }

    return vulns;
  },
}));
