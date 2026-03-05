import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const NOSQL_REGEX =
  /(?:find|findOne|findOneAndUpdate|findOneAndDelete|deleteMany|updateMany|aggregate)\s*\(\s*(?:req\.|request\.|body\.|query\.|\{[^}]*\$(?:where|gt|gte|lt|lte|ne|in|nin|regex|exists))/;

function hasNosqlInjectionAST(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    if (
      node.type === "CallExpression" &&
      node.loc &&
      node.loc.start.line === line &&
      node.callee.type === "MemberExpression" &&
      node.callee.property.type === "Identifier" &&
      /^(find|findOne|findOneAnd|deleteMany|updateMany|aggregate)/.test(
        node.callee.property.name
      ) &&
      node.arguments.length > 0
    ) {
      if (isUserInput(node.arguments[0])) {
        found = true;
      }
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

export const nosqlInjectionRule: Rule = {
  id: "VEXLIT-011",
  name: "NoSQL Injection",
  severity: "critical",
  description: "User input passed directly to MongoDB query operators",
  cwe: "CWE-943",
  owasp: "A03:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Sanitize user input before MongoDB queries. Use mongoose schema validation or express-mongo-sanitize.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      if (!NOSQL_REGEX.test(ctx.lines[i])) continue;
      const lineNum = i + 1;

      if (ast && !hasNosqlInjectionAST(ast, lineNum)) continue;

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "NoSQL injection — user input in MongoDB query",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
      });
    }
    return vulnerabilities;
  },
};
