import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const SQL_INJECTION_PATTERNS: { name: string; pattern: RegExp }[] = [
  {
    name: "String concatenation in SQL query",
    pattern:
      /(?:query|execute|exec|raw)\s*\(\s*["'`](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^"'`]*["'`]\s*\+/i,
  },
  {
    name: "Template literal in SQL query",
    pattern:
      /(?:query|execute|exec|raw)\s*\(\s*`(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^`]*\$\{/i,
  },
  {
    name: "Python f-string SQL query",
    pattern:
      /(?:execute|cursor\.execute|executemany)\s*\(\s*f["'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b/i,
  },
  {
    name: "Python format string SQL query",
    pattern:
      /(?:execute|cursor\.execute)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^"']*["']\.format\s*\(/i,
  },
];

function hasSqlConcatAtLine(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;

    // BinaryExpression with + on the target line
    if (
      node.type === "BinaryExpression" &&
      node.operator === "+" &&
      node.loc &&
      node.loc.start.line === line
    ) {
      // Check if left side contains a SQL keyword string literal
      if (containsSqlLiteral(node.left)) {
        found = true;
      }
    }

    // TemplateLiteral with expressions (template injection)
    if (
      node.type === "TemplateLiteral" &&
      node.loc &&
      node.loc.start.line <= line &&
      node.loc.end.line >= line &&
      node.expressions.length > 0
    ) {
      const quasis = node.quasis.map((q) => q.value.raw).join("");
      if (/\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b/i.test(quasis)) {
        found = true;
      }
    }
  });
  return found;
}

function containsSqlLiteral(node: TSESTree.Node): boolean {
  if (node.type === "Literal" && typeof node.value === "string") {
    return /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b/i.test(node.value);
  }
  if (node.type === "BinaryExpression" && node.operator === "+") {
    return containsSqlLiteral(node.left) || containsSqlLiteral(node.right);
  }
  return false;
}

export const sqlInjectionRule: Rule = {
  id: "VEXLIT-002",
  name: "SQL Injection",
  severity: "critical",
  description: "Potential SQL injection via string concatenation or interpolation",
  cwe: "CWE-89",
  owasp: "A03:2021",
  languages: ["javascript", "typescript", "python"],
  suggestion: "Use parameterized queries or prepared statements instead of string concatenation",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];

      for (const { name, pattern } of SQL_INJECTION_PATTERNS) {
        if (!pattern.test(line)) continue;

        const lineNum = i + 1;

        // AST verification for JS/TS: confirm BinaryExpression or TemplateLiteral
        if (ast && (ctx.language === "javascript" || ctx.language === "typescript")) {
          if (!hasSqlConcatAtLine(ast, lineNum)) continue;
        }

        vulnerabilities.push({
          ruleId: this.id,
          ruleName: this.name,
          severity: this.severity,
          message: `${name} — possible SQL injection`,
          filePath: ctx.filePath,
          line: lineNum,
          column: 1,
          snippet: line.trim(),
          cwe: this.cwe,
          owasp: this.owasp,
          suggestion: this.suggestion,
          confidence: "high",
        });
      }
    }

    return vulnerabilities;
  },
};
