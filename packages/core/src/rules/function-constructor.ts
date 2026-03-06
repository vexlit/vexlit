import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const FUNC_CONSTRUCTOR_REGEX = /new\s+Function\s*\(/;

function hasUnsafeFunctionConstructor(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    if (
      node.type === "NewExpression" &&
      node.loc &&
      node.loc.start.line === line &&
      node.callee.type === "Identifier" &&
      node.callee.name === "Function" &&
      node.arguments.length > 0
    ) {
      // Only flag if argument is NOT a static string literal
      const lastArg = node.arguments[node.arguments.length - 1];
      if (lastArg.type !== "Literal") {
        found = true;
      }
    }
  });
  return found;
}

export const functionConstructorRule: Rule = {
  id: "VEXLIT-009",
  name: "Function Constructor",
  severity: "critical",
  description: "Dynamic code execution via new Function() with non-static input",
  cwe: "CWE-95",
  owasp: "A03:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Avoid new Function() with dynamic input. Use safer alternatives like predefined functions or a sandboxed evaluator.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      if (!FUNC_CONSTRUCTOR_REGEX.test(ctx.lines[i])) continue;
      const lineNum = i + 1;

      if (ast && !hasUnsafeFunctionConstructor(ast, lineNum)) continue;

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "new Function() with dynamic input — code injection risk",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
          confidence: "high",
      });
    }
    return vulnerabilities;
  },
};
