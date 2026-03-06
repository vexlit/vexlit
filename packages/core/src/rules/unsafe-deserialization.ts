import { Rule, Vulnerability, ScanContext } from "../types.js";

const DESERIAL_PATTERNS: { name: string; pattern: RegExp }[] = [
  {
    name: "Node.js unserialize (node-serialize)",
    pattern: /(?:serialize\.unserialize|unserialize)\s*\(/,
  },
  {
    name: "Python pickle.loads",
    pattern: /pickle\.(?:loads?|Unpickler)\s*\(/,
  },
  {
    name: "Python yaml.load (unsafe)",
    pattern: /yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/,
  },
  {
    name: "PHP unserialize",
    pattern: /unserialize\s*\(\s*\$/,
  },
  {
    name: "Java ObjectInputStream",
    pattern: /ObjectInputStream|readObject\s*\(\s*\)/,
  },
];

export const unsafeDeserializationRule: Rule = {
  id: "VEXLIT-020",
  name: "Unsafe Deserialization",
  severity: "critical",
  description: "Deserialization of untrusted data can lead to remote code execution",
  cwe: "CWE-502",
  owasp: "A08:2021",
  languages: ["javascript", "typescript", "python"],
  suggestion: "Avoid deserializing untrusted data. Use safe alternatives (JSON.parse for data, yaml.safe_load for YAML).",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];
      for (const { name, pattern } of DESERIAL_PATTERNS) {
        if (pattern.test(line)) {
          vulnerabilities.push({
            ruleId: this.id, ruleName: this.name, severity: this.severity,
            message: `${name} — unsafe deserialization`,
            filePath: ctx.filePath, line: i + 1, column: 1,
            snippet: line.trim(),
            cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
          confidence: "high",
          });
        }
      }
    }
    return vulnerabilities;
  },
};
