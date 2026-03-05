import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const STACK_TRACE_REGEX =
  /(?:res\.(?:send|json|status)\s*\([^)]*(?:err|error|stack|message)|\.stack\b|console\.(?:log|error)\s*\([^)]*(?:err|error))/;

function hasInfoExposureAST(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    if (!node.loc || node.loc.start.line !== line) return;

    // res.send(err) / res.json({ error: err.stack })
    if (
      node.type === "CallExpression" &&
      node.callee.type === "MemberExpression" &&
      node.callee.property.type === "Identifier" &&
      (node.callee.property.name === "send" || node.callee.property.name === "json")
    ) {
      for (const arg of node.arguments) {
        if (containsErrorObject(arg)) {
          found = true;
          return;
        }
      }
    }
  });
  return found;
}

function containsErrorObject(node: TSESTree.Node): boolean {
  // err, error, e.stack, err.message
  if (node.type === "Identifier" && /^(err|error|e)$/i.test(node.name)) return true;
  if (
    node.type === "MemberExpression" &&
    node.property.type === "Identifier" &&
    (node.property.name === "stack" || node.property.name === "message") &&
    node.object.type === "Identifier" &&
    /^(err|error|e)$/i.test(node.object.name)
  ) {
    return true;
  }
  if (node.type === "ObjectExpression") {
    return node.properties.some(
      (p) =>
        p.type === "Property" &&
        containsErrorObject(p.value)
    );
  }
  return false;
}

export const infoExposureRule: Rule = {
  id: "VEXLIT-016",
  name: "Information Exposure",
  severity: "warning",
  description: "Error details or stack traces sent to client response",
  cwe: "CWE-209",
  owasp: "A04:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Never send raw error objects or stack traces to clients. Log errors server-side and return generic error messages.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      if (!STACK_TRACE_REGEX.test(ctx.lines[i])) continue;
      const lineNum = i + 1;

      if (!ast) continue;
      if (!hasInfoExposureAST(ast, lineNum)) continue;

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "Error details/stack trace exposed to client",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
      });
    }
    return vulnerabilities;
  },
};
