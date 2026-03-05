import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const TLS_REGEX = /rejectUnauthorized\s*[:=]\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*["']0["']/;

function hasInsecureTlsAST(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    if (!node.loc || node.loc.start.line !== line) return;

    // rejectUnauthorized: false
    if (
      node.type === "Property" &&
      node.key.type === "Identifier" &&
      node.key.name === "rejectUnauthorized" &&
      node.value.type === "Literal" &&
      node.value.value === false
    ) {
      found = true;
    }

    // process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"
    if (
      node.type === "AssignmentExpression" &&
      node.right.type === "Literal" &&
      node.right.value === "0" &&
      node.left.type === "MemberExpression" &&
      node.left.property.type === "Identifier" &&
      node.left.property.name === "NODE_TLS_REJECT_UNAUTHORIZED"
    ) {
      found = true;
    }
  });
  return found;
}

export const insecureTlsRule: Rule = {
  id: "VEXLIT-017",
  name: "Insecure TLS Configuration",
  severity: "critical",
  description: "TLS certificate validation disabled, allowing MITM attacks",
  cwe: "CWE-295",
  owasp: "A07:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Never disable TLS certificate verification. Fix certificate issues instead of bypassing validation.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      if (!TLS_REGEX.test(ctx.lines[i])) continue;
      const lineNum = i + 1;

      if (ast && !hasInsecureTlsAST(ast, lineNum)) continue;

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "TLS certificate validation disabled — MITM vulnerability",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
      });
    }
    return vulnerabilities;
  },
};
