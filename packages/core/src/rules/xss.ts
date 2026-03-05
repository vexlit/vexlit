import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const XSS_PATTERNS: { name: string; pattern: RegExp }[] = [
  {
    name: "innerHTML assignment",
    pattern: /\.innerHTML\s*=/,
  },
  {
    name: "document.write usage",
    pattern: /document\.write\s*\(/,
  },
  {
    name: "outerHTML assignment",
    pattern: /\.outerHTML\s*=/,
  },
  {
    name: "dangerouslySetInnerHTML",
    pattern: /dangerouslySetInnerHTML/,
  },
];

function hasInnerHtmlAssignmentAtLine(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;

    // element.innerHTML = something
    if (
      node.type === "AssignmentExpression" &&
      node.loc &&
      node.loc.start.line === line &&
      node.left.type === "MemberExpression" &&
      node.left.property.type === "Identifier" &&
      (node.left.property.name === "innerHTML" || node.left.property.name === "outerHTML")
    ) {
      // Only flag if right side is NOT a static string literal
      if (node.right.type !== "Literal") {
        found = true;
      }
    }
  });
  return found;
}

function hasDocumentWriteAtLine(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;

    if (
      node.type === "CallExpression" &&
      node.loc &&
      node.loc.start.line === line &&
      node.callee.type === "MemberExpression" &&
      node.callee.object.type === "Identifier" &&
      node.callee.object.name === "document" &&
      node.callee.property.type === "Identifier" &&
      node.callee.property.name === "write"
    ) {
      found = true;
    }
  });
  return found;
}

function hasDangerouslySetInnerHTMLAtLine(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;

    // JSX attribute: dangerouslySetInnerHTML={...}
    if (
      node.type === "JSXAttribute" &&
      node.loc &&
      node.loc.start.line === line &&
      node.name.type === "JSXIdentifier" &&
      node.name.name === "dangerouslySetInnerHTML"
    ) {
      found = true;
    }
    // Object property: dangerouslySetInnerHTML: {...}
    if (
      node.type === "Property" &&
      node.loc &&
      node.loc.start.line === line &&
      node.key.type === "Identifier" &&
      node.key.name === "dangerouslySetInnerHTML"
    ) {
      found = true;
    }
  });
  return found;
}

export const xssRule: Rule = {
  id: "VEXLIT-003",
  name: "Cross-Site Scripting (XSS)",
  severity: "warning",
  description: "Potential XSS vulnerability via unsafe DOM manipulation",
  cwe: "CWE-79",
  owasp: "A03:2021",
  languages: ["javascript", "typescript"],
  suggestion: "Sanitize user input before inserting into the DOM. Use textContent or a sanitization library.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];

      for (const { name, pattern } of XSS_PATTERNS) {
        if (!pattern.test(line)) continue;

        const lineNum = i + 1;
        let confirmed = true;

        // AST verification
        if (ast) {
          if (name === "innerHTML assignment" || name === "outerHTML assignment") {
            confirmed = hasInnerHtmlAssignmentAtLine(ast, lineNum);
          } else if (name === "document.write usage") {
            confirmed = hasDocumentWriteAtLine(ast, lineNum);
          } else if (name === "dangerouslySetInnerHTML") {
            confirmed = hasDangerouslySetInnerHTMLAtLine(ast, lineNum);
          }
        }

        if (!confirmed) continue;

        vulnerabilities.push({
          ruleId: this.id,
          ruleName: this.name,
          severity: this.severity,
          message: `${name} — potential XSS vector`,
          filePath: ctx.filePath,
          line: lineNum,
          column: 1,
          snippet: line.trim(),
          cwe: this.cwe,
          owasp: this.owasp,
          suggestion: this.suggestion,
        });
      }
    }

    return vulnerabilities;
  },
};
