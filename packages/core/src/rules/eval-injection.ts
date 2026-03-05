import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const EVAL_REGEX = /\beval\s*\(\s*[^"'`\d)]/;

function hasUnsafeEvalAtLine(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;

    if (
      node.type === "CallExpression" &&
      node.loc &&
      node.loc.start.line === line &&
      node.callee.type === "Identifier" &&
      node.callee.name === "eval"
    ) {
      if (node.arguments.length > 0 && node.arguments[0].type !== "Literal") {
        found = true;
      }
    }
  });
  return found;
}

export const evalInjectionRule: Rule = {
  id: "VEXLIT-023",
  name: "Eval Injection",
  severity: "critical",
  description: "Dynamic code execution via eval() with non-static input",
  cwe: "CWE-95",
  owasp: "A03:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Avoid eval() with dynamic input. Use JSON.parse(), predefined functions, or a sandboxed evaluator instead.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      if (!EVAL_REGEX.test(ctx.lines[i])) continue;
      const lineNum = i + 1;

      if (ast && !hasUnsafeEvalAtLine(ast, lineNum)) continue;

      vulnerabilities.push({
        ruleId: this.id,
        ruleName: this.name,
        severity: this.severity,
        message: "eval() with dynamic input — code injection risk",
        filePath: ctx.filePath,
        line: lineNum,
        column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe,
        owasp: this.owasp,
        suggestion: this.suggestion,
      });
    }
    return vulnerabilities;
  },
};
