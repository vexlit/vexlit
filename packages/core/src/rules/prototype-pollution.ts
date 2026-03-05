import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const PROTO_REGEX = /__proto__|Object\.assign\s*\(\s*\{|\.constructor\.prototype/;

function hasPrototypePollutionAST(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    if (!node.loc || node.loc.start.line !== line) return;

    // __proto__ access
    if (
      node.type === "MemberExpression" &&
      node.property.type === "Identifier" &&
      node.property.name === "__proto__"
    ) {
      found = true;
    }

    // Object.assign({}, req.body) — merge user input into fresh object
    if (
      node.type === "CallExpression" &&
      node.callee.type === "MemberExpression" &&
      node.callee.object.type === "Identifier" &&
      node.callee.object.name === "Object" &&
      node.callee.property.type === "Identifier" &&
      node.callee.property.name === "assign"
    ) {
      for (const arg of node.arguments) {
        if (isUserInput(arg)) {
          found = true;
          return;
        }
      }
    }

    // .constructor.prototype
    if (
      node.type === "MemberExpression" &&
      node.property.type === "Identifier" &&
      node.property.name === "prototype" &&
      node.object.type === "MemberExpression" &&
      node.object.property.type === "Identifier" &&
      node.object.property.name === "constructor"
    ) {
      found = true;
    }
  });
  return found;
}

function isUserInput(node: TSESTree.Node): boolean {
  if (node.type === "MemberExpression") {
    const src = flattenMember(node);
    return /^(req|request)\.(body|query|params)/.test(src);
  }
  return false;
}

function flattenMember(node: TSESTree.MemberExpression): string {
  const prop = node.property.type === "Identifier" ? node.property.name : "?";
  if (node.object.type === "Identifier") return `${node.object.name}.${prop}`;
  if (node.object.type === "MemberExpression") return `${flattenMember(node.object)}.${prop}`;
  return prop;
}

export const prototypePollutionRule: Rule = {
  id: "VEXLIT-010",
  name: "Prototype Pollution",
  severity: "critical",
  description: "Potential prototype pollution via __proto__ access or Object.assign with user input",
  cwe: "CWE-1321",
  owasp: "A03:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Use Object.create(null) for lookup objects. Validate/strip __proto__ and constructor keys from user input. Use Map instead of plain objects.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      if (!PROTO_REGEX.test(ctx.lines[i])) continue;
      const lineNum = i + 1;

      if (ast && !hasPrototypePollutionAST(ast, lineNum)) continue;

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "Prototype pollution — __proto__ or unsafe Object.assign with user input",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
      });
    }
    return vulnerabilities;
  },
};
