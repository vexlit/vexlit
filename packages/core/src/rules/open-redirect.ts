import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const REDIRECT_REGEX =
  /(?:res\.redirect|response\.redirect|window\.location|location\.href|location\.assign|location\.replace)\s*[\(=]\s*(?:req\.|request\.|params\.|query\.)/;

function hasUnsafeRedirectAST(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    if (node.loc && node.loc.start.line !== line) return;

    // res.redirect(req.query.url)
    if (
      node.type === "CallExpression" &&
      node.callee.type === "MemberExpression" &&
      node.callee.property.type === "Identifier" &&
      (node.callee.property.name === "redirect" ||
        node.callee.property.name === "assign" ||
        node.callee.property.name === "replace") &&
      node.arguments.length > 0 &&
      isUserInput(node.arguments[node.arguments.length - 1])
    ) {
      found = true;
    }

    // location.href = req.query.url
    if (
      node.type === "AssignmentExpression" &&
      node.left.type === "MemberExpression" &&
      node.left.property.type === "Identifier" &&
      node.left.property.name === "href" &&
      isUserInput(node.right)
    ) {
      found = true;
    }
  });
  return found;
}

function isUserInput(node: TSESTree.Node): boolean {
  if (node.type === "MemberExpression") {
    const src = flattenMember(node);
    return /^(req|request)\.(query|params|body|headers)/.test(src);
  }
  return false;
}

function flattenMember(node: TSESTree.MemberExpression): string {
  const prop = node.property.type === "Identifier" ? node.property.name : "?";
  if (node.object.type === "Identifier") return `${node.object.name}.${prop}`;
  if (node.object.type === "MemberExpression") return `${flattenMember(node.object)}.${prop}`;
  return prop;
}

export const openRedirectRule: Rule = {
  id: "VEXLIT-006",
  name: "Open Redirect",
  severity: "warning",
  description: "User-controlled input used in URL redirect without validation",
  cwe: "CWE-601",
  owasp: "A01:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Validate redirect URLs against an allowlist of trusted domains. Never redirect to user-supplied URLs directly.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      if (!REDIRECT_REGEX.test(ctx.lines[i])) continue;
      const lineNum = i + 1;

      if (ast && !hasUnsafeRedirectAST(ast, lineNum)) continue;

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "Open redirect — user input used in URL redirect",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
          confidence: "high",
      });
    }
    return vulnerabilities;
  },
};
