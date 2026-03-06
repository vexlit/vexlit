import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const PROTO_REGEX =
  /__proto__|Object\.assign\s*\(|\.constructor\.prototype|for\s*\(.*\bin\b|_\.merge\s*\(|lodash\.merge\s*\(|merge\s*\(|deepmerge\s*\(/;

function hasPrototypePollutionAST(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    if (!node.loc) return;

    // for..in loop with direct assignment (no hasOwnProperty guard)
    if (
      node.type === "ForInStatement" &&
      node.loc.start.line <= line &&
      node.loc.end.line >= line
    ) {
      if (!hasHasOwnPropertyGuard(node.body)) {
        found = true;
      }
      return;
    }

    if (node.loc.start.line !== line) return;

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

    // lodash.merge / _.merge / deepmerge calls
    if (node.type === "CallExpression" && node.loc?.start.line === line) {
      const name = getCallName(node);
      if (
        name === "_.merge" ||
        name === "_.defaultsDeep" ||
        name === "lodash.merge" ||
        name === "merge" ||
        name === "deepmerge"
      ) {
        found = true;
      }
    }
  });
  return found;
}

function hasHasOwnPropertyGuard(body: TSESTree.Node): boolean {
  let hasGuard = false;
  walkAST(body as AST, (node: TSESTree.Node) => {
    if (hasGuard) return;
    // if (obj.hasOwnProperty(key)) or if (Object.hasOwn(obj, key))
    if (node.type === "CallExpression") {
      const name = getCallName(node);
      if (
        name?.endsWith(".hasOwnProperty") ||
        name === "Object.hasOwn" ||
        name === "Object.prototype.hasOwnProperty.call"
      ) {
        hasGuard = true;
      }
    }
  });
  return hasGuard;
}

function getCallName(node: TSESTree.CallExpression): string | null {
  if (node.callee.type === "Identifier") return node.callee.name;
  if (node.callee.type === "MemberExpression") return flattenMember(node.callee);
  return null;
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
        message: "Prototype pollution — unsafe object merge or __proto__ access",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
          confidence: "high",
      });
    }
    return vulnerabilities;
  },
};
