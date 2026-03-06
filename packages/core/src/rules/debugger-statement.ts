import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { AST } from "../ast-parser.js";
import { findNodes } from "../ast-parser.js";

const DEBUGGER_REGEX = /^\s*debugger\s*;?\s*$/;

export const debuggerStatementRule: Rule = {
  id: "VEXLIT-019",
  name: "Debugger Statement",
  severity: "info",
  description: "Debugger statement left in production code",
  cwe: "CWE-489",
  owasp: "A05:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Remove all debugger statements before deploying to production.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    if (ast) {
      const nodes = findNodes(ast, "DebuggerStatement");
      for (const node of nodes) {
        if (!node.loc) continue;
        vulnerabilities.push({
          ruleId: this.id, ruleName: this.name, severity: this.severity,
          message: "debugger statement left in code",
          filePath: ctx.filePath,
          line: node.loc.start.line,
          column: node.loc.start.column + 1,
          snippet: ctx.lines[node.loc.start.line - 1]?.trim() ?? "debugger",
          cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
          confidence: "high",
        });
      }
    } else {
      // Fallback to regex for non-AST files
      for (let i = 0; i < ctx.lines.length; i++) {
        if (DEBUGGER_REGEX.test(ctx.lines[i])) {
          vulnerabilities.push({
            ruleId: this.id, ruleName: this.name, severity: this.severity,
            message: "debugger statement left in code",
            filePath: ctx.filePath, line: i + 1, column: 1,
            snippet: ctx.lines[i].trim(),
            cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
          confidence: "high",
          });
        }
      }
    }
    return vulnerabilities;
  },
};
