import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const CORS_REGEX = /(?:Access-Control-Allow-Origin|origin\s*[:=]\s*["'`]\*["'`]|cors\s*\(\s*\))/;

function hasCORSWildcardAST(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    if (!node.loc || node.loc.start.line !== line) return;

    // origin: "*"
    if (
      node.type === "Property" &&
      node.key.type === "Identifier" &&
      node.key.name === "origin" &&
      node.value.type === "Literal" &&
      node.value.value === "*"
    ) {
      found = true;
    }

    // origin: true (reflects any origin)
    if (
      node.type === "Property" &&
      node.key.type === "Identifier" &&
      node.key.name === "origin" &&
      node.value.type === "Literal" &&
      node.value.value === true
    ) {
      found = true;
    }

    // cors() with no arguments
    if (
      node.type === "CallExpression" &&
      node.callee.type === "Identifier" &&
      node.callee.name === "cors" &&
      node.arguments.length === 0
    ) {
      found = true;
    }

    // setHeader("Access-Control-Allow-Origin", "*")
    if (
      node.type === "CallExpression" &&
      node.callee.type === "MemberExpression" &&
      node.callee.property.type === "Identifier" &&
      node.callee.property.name === "setHeader" &&
      node.arguments.length >= 2 &&
      node.arguments[0].type === "Literal" &&
      node.arguments[0].value === "Access-Control-Allow-Origin" &&
      node.arguments[1].type === "Literal" &&
      node.arguments[1].value === "*"
    ) {
      found = true;
    }
  });
  return found;
}

export const corsMisconfigurationRule: Rule = {
  id: "VEXLIT-014",
  name: "CORS Misconfiguration",
  severity: "warning",
  description: "CORS configured to allow all origins",
  cwe: "CWE-942",
  owasp: "A05:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Restrict CORS origin to specific trusted domains. Never use wildcard '*' with credentials.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      if (!CORS_REGEX.test(ctx.lines[i])) continue;
      const lineNum = i + 1;

      if (ast && !hasCORSWildcardAST(ast, lineNum)) continue;

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "CORS allows all origins — potential data exposure",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
          confidence: "high",
      });
    }
    return vulnerabilities;
  },
};
