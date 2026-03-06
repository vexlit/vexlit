import { Rule, Vulnerability, ScanContext } from "../types.js";

// Detect nested quantifiers that can cause catastrophic backtracking
// Patterns like (a+)+ , (a*)*b , (a|b)* etc with nested repetition
const REDOS_PATTERNS: RegExp[] = [
  // Nested quantifiers: (x+)+ , (x+)* , (x*)+ , (x*)*
  /\([^)]*[+*]\)[+*]/,
  // Overlapping alternation with quantifier: (a|a)+
  /\([^)]*\|[^)]*\)[+*]{1,}/,
  // Nested groups with quantifiers: ((x)+)+
  /\(\([^)]*\)[+*]\)[+*]/,
];

const REGEX_CONSTRUCTOR = /new\s+RegExp\s*\(/;
const REGEX_LITERAL = /\/[^/]+\/[gimsuy]*/;

export const redosRule: Rule = {
  id: "VEXLIT-015",
  name: "Regular Expression DoS (ReDoS)",
  severity: "warning",
  description: "Regular expression with nested quantifiers vulnerable to catastrophic backtracking",
  cwe: "CWE-1333",
  owasp: "A06:2021",
  languages: ["javascript", "typescript", "python"],
  suggestion: "Avoid nested quantifiers in regex. Use atomic groups or possessive quantifiers. Set timeouts for regex operations.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];

      // Only check lines that contain regex
      if (!REGEX_CONSTRUCTOR.test(line) && !REGEX_LITERAL.test(line)) continue;

      for (const pattern of REDOS_PATTERNS) {
        if (pattern.test(line)) {
          vulnerabilities.push({
            ruleId: this.id, ruleName: this.name, severity: this.severity,
            message: "ReDoS — regex with nested quantifiers vulnerable to catastrophic backtracking",
            filePath: ctx.filePath, line: i + 1, column: 1,
            snippet: line.trim(),
            cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
          confidence: "high",
          });
          break;
        }
      }
    }
    return vulnerabilities;
  },
};
