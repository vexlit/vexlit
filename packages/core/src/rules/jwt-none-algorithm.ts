import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const JWT_ALGO_REGEX = /algorithm[s]?\s*[:=]\s*["'`]none["'`]/i;

function hasNoneAlgorithmAST(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    // { algorithm: "none" } or { algorithms: ["none"] }
    if (
      node.type === "Property" &&
      node.loc &&
      node.loc.start.line === line &&
      node.key.type === "Identifier" &&
      (node.key.name === "algorithm" || node.key.name === "algorithms")
    ) {
      if (node.value.type === "Literal" && node.value.value === "none") {
        found = true;
      }
      if (
        node.value.type === "ArrayExpression" &&
        node.value.elements.some(
          (el) => el && el.type === "Literal" && el.value === "none"
        )
      ) {
        found = true;
      }
    }
  });
  return found;
}

export const jwtNoneAlgorithmRule: Rule = {
  id: "VEXLIT-008",
  name: "JWT None Algorithm",
  severity: "critical",
  description: "JWT configured with 'none' algorithm, allowing unsigned tokens",
  cwe: "CWE-327",
  owasp: "A02:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Never allow the 'none' algorithm. Use RS256 or HS256 with a strong secret.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      if (!JWT_ALGO_REGEX.test(ctx.lines[i])) continue;
      const lineNum = i + 1;

      if (ast && !hasNoneAlgorithmAST(ast, lineNum)) continue;

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "JWT 'none' algorithm allows unsigned tokens",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
          confidence: "high",
      });
    }
    return vulnerabilities;
  },
};
