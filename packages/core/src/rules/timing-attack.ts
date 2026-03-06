import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const TIMING_REGEX =
  /(?:password|secret|token|hash|key|signature|apiKey|api_key)\s*(?:===|==|!==|!=)\s*/i;

const SECRET_NAMES = /^(password|secret|token|hash|key|signature|apikey|api_key|digest|hmac)$/i;

function hasTimingComparisonAST(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    if (!node.loc || node.loc.start.line !== line) return;

    if (
      node.type === "BinaryExpression" &&
      (node.operator === "===" || node.operator === "==" ||
        node.operator === "!==" || node.operator === "!=")
    ) {
      if (isSecretIdentifier(node.left) || isSecretIdentifier(node.right)) {
        found = true;
      }
    }
  });
  return found;
}

function isSecretIdentifier(node: TSESTree.Node): boolean {
  if (node.type === "Identifier" && SECRET_NAMES.test(node.name)) return true;
  if (
    node.type === "MemberExpression" &&
    node.property.type === "Identifier" &&
    SECRET_NAMES.test(node.property.name)
  ) {
    return true;
  }
  return false;
}

export const timingAttackRule: Rule = {
  id: "VEXLIT-018",
  name: "Timing Attack",
  severity: "warning",
  description: "Non-constant-time string comparison for secrets or tokens",
  cwe: "CWE-208",
  owasp: "A02:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Use crypto.timingSafeEqual() for comparing secrets, tokens, or hashes. Never use === or == for secret comparison.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      if (!TIMING_REGEX.test(ctx.lines[i])) continue;
      const lineNum = i + 1;

      if (!ast) continue;
      if (!hasTimingComparisonAST(ast, lineNum)) continue;

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "Timing attack — non-constant-time comparison of secret value",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
          confidence: "high",
      });
    }
    return vulnerabilities;
  },
};
