import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const JWT_SIGN_REGEX = /jwt\.sign\s*\(/;
const JWT_VERIFY_REGEX = /jwt\.verify\s*\(/;

function hasHardcodedJwtSecret(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    if (
      node.type === "CallExpression" &&
      node.loc &&
      node.loc.start.line === line &&
      node.callee.type === "MemberExpression" &&
      node.callee.property.type === "Identifier" &&
      (node.callee.property.name === "sign" || node.callee.property.name === "verify")
    ) {
      // jwt.sign(payload, "hardcoded-secret") — 2nd arg is secret
      // jwt.verify(token, "hardcoded-secret") — 2nd arg is secret
      if (node.arguments.length >= 2) {
        const secretArg = node.arguments[1];
        if (secretArg.type === "Literal" && typeof secretArg.value === "string") {
          found = true;
        }
      }
    }
  });
  return found;
}

export const jwtHardcodedSecretRule: Rule = {
  id: "VEXLIT-007",
  name: "Hardcoded JWT Secret",
  severity: "critical",
  description: "JWT signing/verification with a hardcoded secret string",
  cwe: "CWE-798",
  owasp: "A02:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Store JWT secrets in environment variables or a secrets manager. Never hardcode them.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];
      if (!JWT_SIGN_REGEX.test(line) && !JWT_VERIFY_REGEX.test(line)) continue;
      const lineNum = i + 1;

      if (ast && !hasHardcodedJwtSecret(ast, lineNum)) continue;
      // Without AST, regex match alone is not sufficient — skip
      if (!ast) continue;

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "Hardcoded JWT secret in jwt.sign/jwt.verify",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: line.trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
      });
    }
    return vulnerabilities;
  },
};
