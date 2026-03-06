import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";
import type { TreeSitterTree, TreeSitterNode } from "../tree-sitter.js";
import { walkTreeSitter } from "../tree-sitter.js";
import { collectJsSanitizedVars, collectPySanitizedVars, collectPySanitizedVarsRegex, isJsSanitizerCall, surroundingHasSanitizer } from "../sanitizers.js";

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
  {
    name: "Express response injection",
    pattern: /res\.send\s*\(\s*`/,
  },
  {
    name: "Express response HTML concatenation",
    pattern: /res\.send\s*\(\s*["']<[^"']*["']\s*\+/,
  },
];

function hasInnerHtmlAssignmentAtLine(ast: AST, line: number, sanitizedVars: Map<string, Set<string>>): boolean {
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
      // Safe: static string literal
      if (node.right.type === "Literal") return;
      // Safe: sanitizer call — DOMPurify.sanitize(x), sanitizeHtml(x)
      if (isJsSanitizerCall(node.right, "xss")) return;
      // Safe: variable that was previously sanitized
      if (node.right.type === "Identifier" && sanitizedVars.get(node.right.name)?.has("xss")) return;
      found = true;
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

function hasResSendWithTemplateAtLine(ast: AST, line: number, sanitizedVars: Map<string, Set<string>>): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;

    if (
      node.type === "CallExpression" &&
      node.loc &&
      node.loc.start.line === line &&
      node.callee.type === "MemberExpression" &&
      node.callee.property.type === "Identifier" &&
      node.callee.property.name === "send" &&
      node.arguments.length > 0
    ) {
      const firstArg = node.arguments[0];
      // res.send(`...${expr}...`)
      if (firstArg.type === "TemplateLiteral" && firstArg.expressions.length > 0) {
        // Safe if all interpolated expressions are sanitized
        const allSanitized = firstArg.expressions.every((expr) =>
          isJsSanitizerCall(expr, "xss") ||
          (expr.type === "Identifier" && sanitizedVars.get(expr.name)?.has("xss"))
        );
        if (!allSanitized) found = true;
        return;
      }
      // res.send("<h1>" + name + "</h1>")
      if (firstArg.type === "BinaryExpression" && firstArg.operator === "+") {
        if (containsHtmlLiteral(firstArg) && !binaryAllSanitized(firstArg, sanitizedVars)) {
          found = true;
          return;
        }
      }
    }
  });
  return found;
}

function binaryAllSanitized(node: TSESTree.Node, sanitizedVars: Map<string, Set<string>>): boolean {
  if (node.type === "Literal") return true;
  if (node.type === "Identifier") return !!sanitizedVars.get(node.name)?.has("xss");
  if (isJsSanitizerCall(node, "xss")) return true;
  if (node.type === "BinaryExpression" && node.operator === "+") {
    return binaryAllSanitized(node.left, sanitizedVars) && binaryAllSanitized(node.right, sanitizedVars);
  }
  return false;
}

function containsHtmlLiteral(node: TSESTree.Node): boolean {
  if (node.type === "Literal" && typeof node.value === "string") {
    return /<[a-zA-Z]/.test(node.value);
  }
  if (node.type === "BinaryExpression" && node.operator === "+") {
    return containsHtmlLiteral(node.left) || containsHtmlLiteral(node.right);
  }
  return false;
}

// ── Python XSS detection ──

const PY_XSS_PATTERNS: { name: string; pattern: RegExp }[] = [
  {
    name: "Flask make_response with f-string HTML",
    pattern: /\b(?:make_response|Response)\s*\(\s*f["']<[^"']*\{/,
  },
  {
    name: "Flask return with f-string HTML",
    pattern: /\breturn\s+f["']<[^"']*\{/,
  },
  {
    name: "Flask return with format HTML",
    pattern: /\breturn\s+["']<[^"']*["']\.format\s*\(/,
  },
  {
    name: "Flask return with % format HTML",
    pattern: /\breturn\s+["']<[^"']*%s[^"']*["']\s*%/,
  },
  {
    name: "Django mark_safe with dynamic content",
    pattern: /\bmark_safe\s*\(\s*f["']/,
  },
  {
    name: "Django mark_safe with format",
    pattern: /\bmark_safe\s*\(\s*["'][^"']*["']\.format\s*\(/,
  },
];

const PY_USER_INPUT_XSS = /\b(?:request\.\w+|input\s*\()/;

function scanPyXss(ctx: ScanContext): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  const tree = ctx.treeSitterTree as TreeSitterTree | null;

  if (tree) {
    return scanPyXssTreeSitter(ctx, tree);
  }

  // Regex fallback
  const sanitizedRegex = collectPySanitizedVarsRegex(ctx.lines, "xss");
  for (let i = 0; i < ctx.lines.length; i++) {
    const line = ctx.lines[i];
    for (const { name, pattern } of PY_XSS_PATTERNS) {
      if (!pattern.test(line)) continue;

      // Skip if line only uses sanitized variables
      if ([...sanitizedRegex].some((v) => new RegExp(`\\b${v}\\b`).test(line)) &&
          !PY_USER_INPUT_XSS.test(line)) continue;

      const isTainted = PY_USER_INPUT_XSS.test(line);
      vulns.push({
        ruleId: "VEXLIT-003",
        ruleName: "Cross-Site Scripting (XSS)",
        severity: "critical",
        confidence: isTainted ? "high" : "medium",
        message: `${name} — potential XSS vector`,
        filePath: ctx.filePath,
        line: i + 1,
        column: 1,
        snippet: line.trim(),
        cwe: "CWE-79",
        owasp: "A03:2021",
        suggestion: "Never interpolate user input into HTML responses. Use template engines with auto-escaping (Jinja2 autoescaping, Django templates).",
      });
      break; // one finding per line
    }
  }
  return vulns;
}

function scanPyXssTreeSitter(ctx: ScanContext, tree: TreeSitterTree): Vulnerability[] {
  const vulns: Vulnerability[] = [];

  // Collect tainted variables
  const tainted = new Set<string>();
  walkTreeSitter(tree.rootNode, (node: TreeSitterNode) => {
    if (node.type !== "assignment") return;
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (!left || !right || left.type !== "identifier") return;
    if (PY_USER_INPUT_XSS.test(right.text)) tainted.add(left.text);
  });

  // Collect sanitized variables (html.escape, markupsafe.escape, bleach.clean)
  const sanitized = collectPySanitizedVars(tree.rootNode, walkTreeSitter, "xss");
  // Remove sanitized vars from tainted set
  for (const v of sanitized) tainted.delete(v);

  walkTreeSitter(tree.rootNode, (node: TreeSitterNode) => {
    if (node.type !== "call" && node.type !== "return_statement") return;

    const lineText = ctx.lines[node.startPosition.row] ?? "";

    for (const { name, pattern } of PY_XSS_PATTERNS) {
      if (!pattern.test(lineText)) continue;

      const isTainted =
        PY_USER_INPUT_XSS.test(lineText) ||
        [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(lineText));

      // Skip if only sanitized variables are used on this line
      if (!isTainted && [...sanitized].some((v) => new RegExp(`\\b${v}\\b`).test(lineText))) continue;

      vulns.push({
        ruleId: "VEXLIT-003",
        ruleName: "Cross-Site Scripting (XSS)",
        severity: "critical",
        confidence: isTainted ? "high" : "medium",
        message: `${name} — potential XSS vector`,
        filePath: ctx.filePath,
        line: node.startPosition.row + 1,
        column: 1,
        snippet: lineText.trim(),
        cwe: "CWE-79",
        owasp: "A03:2021",
        suggestion: "Never interpolate user input into HTML responses. Use template engines with auto-escaping (Jinja2 autoescaping, Django templates).",
      });
      break;
    }
  });

  return vulns;
}

// ── Rule export ──

export const xssRule: Rule = {
  id: "VEXLIT-003",
  name: "Cross-Site Scripting (XSS)",
  severity: "warning",
  description: "Potential XSS vulnerability via unsafe DOM manipulation or unescaped HTML response",
  cwe: "CWE-79",
  owasp: "A03:2021",
  languages: ["javascript", "typescript", "python"],
  suggestion: "Sanitize user input before inserting into the DOM. Use textContent or a sanitization library.",

  scan(ctx: ScanContext): Vulnerability[] {
    if (ctx.language === "python") {
      return scanPyXss(ctx);
    }

    // JS/TS detection
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    // Collect sanitized variables for FP reduction
    const sanitizedVars = ast
      ? collectJsSanitizedVars(ast, walkAST as (a: unknown, v: (n: TSESTree.Node) => void) => void)
      : new Map<string, Set<string>>();

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];

      for (const { name, pattern } of XSS_PATTERNS) {
        if (!pattern.test(line)) continue;

        const lineNum = i + 1;
        let confirmed = true;

        // AST verification
        if (ast) {
          if (name === "innerHTML assignment" || name === "outerHTML assignment") {
            confirmed = hasInnerHtmlAssignmentAtLine(ast, lineNum, sanitizedVars);
          } else if (name === "document.write usage") {
            confirmed = hasDocumentWriteAtLine(ast, lineNum);
          } else if (name === "dangerouslySetInnerHTML") {
            confirmed = hasDangerouslySetInnerHTMLAtLine(ast, lineNum);
          } else if (name === "Express response injection" || name === "Express response HTML concatenation") {
            confirmed = hasResSendWithTemplateAtLine(ast, lineNum, sanitizedVars);
          }
        }

        if (!confirmed) continue;

        // Context-aware confidence: lower if surrounding lines contain sanitizer calls
        let confidence: "high" | "medium" | "low" = "high";
        if (surroundingHasSanitizer(ctx.lines, i, "xss", ctx.language as "javascript" | "typescript")) {
          confidence = "medium";
        }

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
          confidence,
        });
      }
    }

    return vulnerabilities;
  },
};
