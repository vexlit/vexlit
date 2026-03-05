import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const SSRF_REGEX =
  /(?:fetch|axios\.get|axios\.post|axios\(|http\.get|http\.request|https\.get|https\.request|got\(|request\()\s*\(\s*(?:req\.|request\.|query\.|params\.|body\.|`)/;

const HTTP_CALLEES = new Set([
  "fetch", "get", "post", "put", "patch", "delete", "request",
]);

function hasSsrfAST(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    if (
      node.type === "CallExpression" &&
      node.loc &&
      node.loc.start.line === line &&
      node.arguments.length > 0
    ) {
      const calleeName = getCalleeName(node.callee);
      if (calleeName && HTTP_CALLEES.has(calleeName)) {
        const firstArg = node.arguments[0];
        if (isUserInput(firstArg)) {
          found = true;
        }
        if (firstArg.type === "TemplateLiteral" && firstArg.expressions.length > 0) {
          for (const expr of firstArg.expressions) {
            if (isUserInput(expr)) {
              found = true;
              return;
            }
          }
        }
      }
    }
  });
  return found;
}

function getCalleeName(callee: TSESTree.Node): string | null {
  if (callee.type === "Identifier") return callee.name;
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier")
    return callee.property.name;
  return null;
}

function isUserInput(node: TSESTree.Node): boolean {
  if (node.type === "MemberExpression") {
    const src = flattenMember(node);
    return /^(req|request)\.(body|query|params|headers)/.test(src);
  }
  return false;
}

function flattenMember(node: TSESTree.MemberExpression): string {
  const prop = node.property.type === "Identifier" ? node.property.name : "?";
  if (node.object.type === "Identifier") return `${node.object.name}.${prop}`;
  if (node.object.type === "MemberExpression") return `${flattenMember(node.object)}.${prop}`;
  return prop;
}

export const ssrfRule: Rule = {
  id: "VEXLIT-012",
  name: "Server-Side Request Forgery (SSRF)",
  severity: "critical",
  description: "User-controlled URL passed to server-side HTTP request",
  cwe: "CWE-918",
  owasp: "A10:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Validate and sanitize URLs. Use an allowlist of permitted domains. Block internal/private IP ranges.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      if (!SSRF_REGEX.test(ctx.lines[i])) continue;
      const lineNum = i + 1;

      if (ast && !hasSsrfAST(ast, lineNum)) continue;

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "SSRF — user-controlled URL in server-side HTTP request",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
      });
    }
    return vulnerabilities;
  },
};
