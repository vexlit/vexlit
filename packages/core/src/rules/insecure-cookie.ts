import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const COOKIE_REGEX = /(?:\.cookie\s*\(|cookie\s*[:=]|session\s*[:=]|Set-Cookie)/;

function hasMissingCookieFlagsAST(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    if (!node.loc || node.loc.start.line !== line) return;

    // res.cookie("name", "value", { ... }) — check options object
    if (
      node.type === "CallExpression" &&
      node.callee.type === "MemberExpression" &&
      node.callee.property.type === "Identifier" &&
      node.callee.property.name === "cookie" &&
      node.arguments.length >= 3
    ) {
      const options = node.arguments[2];
      if (options.type === "ObjectExpression") {
        const hasHttpOnly = options.properties.some(
          (p) =>
            p.type === "Property" &&
            p.key.type === "Identifier" &&
            p.key.name === "httpOnly" &&
            p.value.type === "Literal" &&
            p.value.value === true
        );
        const hasSecure = options.properties.some(
          (p) =>
            p.type === "Property" &&
            p.key.type === "Identifier" &&
            p.key.name === "secure" &&
            p.value.type === "Literal" &&
            p.value.value === true
        );
        if (!hasHttpOnly || !hasSecure) {
          found = true;
        }
      } else {
        // Options not an object literal — can't verify
        found = true;
      }
    }

    // res.cookie("name", "value") — no options at all
    if (
      node.type === "CallExpression" &&
      node.callee.type === "MemberExpression" &&
      node.callee.property.type === "Identifier" &&
      node.callee.property.name === "cookie" &&
      node.arguments.length === 2
    ) {
      found = true;
    }
  });
  return found;
}

export const insecureCookieRule: Rule = {
  id: "VEXLIT-013",
  name: "Insecure Cookie",
  severity: "warning",
  description: "Cookie set without httpOnly and/or secure flags",
  cwe: "CWE-614",
  owasp: "A05:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Set httpOnly: true and secure: true on all cookies. Add sameSite: 'strict' for CSRF protection.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      if (!COOKIE_REGEX.test(ctx.lines[i])) continue;
      const lineNum = i + 1;

      // AST-only rule for JS/TS — regex too noisy alone
      if (!ast) continue;
      if (!hasMissingCookieFlagsAST(ast, lineNum)) continue;

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "Cookie missing httpOnly and/or secure flags",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
          confidence: "high",
      });
    }
    return vulnerabilities;
  },
};
