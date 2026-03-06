import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";
import type { TreeSitterTree, TreeSitterNode } from "../tree-sitter.js";
import { walkTreeSitter } from "../tree-sitter.js";

// ── Shared ──

const SQL_KEYWORDS = /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b/i;

// ── JS/TS detection ──

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
      if (SQL_KEYWORDS.test(quasis)) {
        found = true;
      }
    }
  });
  return found;
}

function containsSqlLiteral(node: TSESTree.Node): boolean {
  if (node.type === "Literal" && typeof node.value === "string") {
    return SQL_KEYWORDS.test(node.value);
  }
  if (node.type === "BinaryExpression" && node.operator === "+") {
    return containsSqlLiteral(node.left) || containsSqlLiteral(node.right);
  }
  return false;
}

// ── Python detection ──

const PY_SQL_INLINE_PATTERNS: { name: string; pattern: RegExp }[] = [
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
  {
    name: "Python % format SQL query",
    pattern:
      /(?:execute|cursor\.execute)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^"']*%s[^"']*["']\s*%/i,
  },
  {
    name: "Python SQL concatenation inline",
    pattern:
      /(?:execute|cursor\.execute)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^"']*["']\s*\+/i,
  },
];

const PY_USER_INPUT = /\b(?:request\.\w+|input\s*\(|sys\.argv)/;

function scanPySql(ctx: ScanContext): Vulnerability[] {
  const tree = ctx.treeSitterTree as TreeSitterTree | null;
  if (tree) return scanPySqlTreeSitter(ctx, tree);
  return scanPySqlRegex(ctx);
}

function scanPySqlTreeSitter(ctx: ScanContext, tree: TreeSitterTree): Vulnerability[] {
  const vulns: Vulnerability[] = [];

  // Track variables containing SQL strings built from concatenation/f-string
  const sqlTainted = new Set<string>();

  walkTreeSitter(tree.rootNode, (node: TreeSitterNode) => {
    if (node.type !== "assignment") return;
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (!left || !right || left.type !== "identifier") return;

    // query = "SELECT..." + var  or  query = f"SELECT...{var}"
    if (SQL_KEYWORDS.test(right.text)) {
      // Check if it's a dynamic SQL (concat, f-string, format)
      const isDynamic =
        right.type === "binary_operator" ||
        (right.type === "string" && right.namedChildren.length > 0) || // f-string
        right.type === "call"; // "...".format(...)
      if (isDynamic) {
        sqlTainted.add(left.text);
      }
    }
  });

  walkTreeSitter(tree.rootNode, (node: TreeSitterNode) => {
    if (node.type !== "call") return;
    const func = node.childForFieldName("function");
    if (!func) return;

    // Match: *.execute(...) or execute(...)
    let funcName: string | null = null;
    if (func.type === "attribute") {
      const attr = func.childForFieldName("attribute");
      if (attr) funcName = attr.text;
    } else if (func.type === "identifier") {
      funcName = func.text;
    }
    if (!funcName || (funcName !== "execute" && funcName !== "executemany")) return;

    const argsNode = node.childForFieldName("arguments");
    if (!argsNode || argsNode.namedChildren.length === 0) return;
    const firstArg = argsNode.namedChildren[0];

    // Safe: parameterized query (string literal followed by comma with params)
    if (firstArg.type === "string" && firstArg.namedChildren.length === 0) return;

    // Case A: Inline SQL — f-string or concat directly in execute()
    if (SQL_KEYWORDS.test(firstArg.text)) {
      const isDynamic =
        firstArg.type === "binary_operator" ||
        (firstArg.type === "string" && firstArg.namedChildren.length > 0) ||
        firstArg.type === "call";
      if (isDynamic) {
        vulns.push(makeSqlVuln(ctx, node.startPosition.row + 1, true));
        return;
      }
    }

    // Case B: Variable-flow — execute(query) where query was built dynamically
    if (firstArg.type === "identifier" && sqlTainted.has(firstArg.text)) {
      vulns.push(makeSqlVuln(ctx, node.startPosition.row + 1, true));
    }
  });

  return vulns;
}

function scanPySqlRegex(ctx: ScanContext): Vulnerability[] {
  const vulns: Vulnerability[] = [];

  // Track SQL-tainted variables: query = "SELECT..." + var
  const sqlTainted = new Set<string>();
  for (const l of ctx.lines) {
    const m = l.match(/^\s*(\w+)\s*=/);
    if (!m) continue;
    const rhs = l.slice(l.indexOf("=") + 1);
    if (SQL_KEYWORDS.test(rhs) && /[+]|\.format\s*\(|^.*f["']/.test(rhs)) {
      sqlTainted.add(m[1]);
    }
  }

  for (let i = 0; i < ctx.lines.length; i++) {
    const line = ctx.lines[i];

    // Check inline patterns first
    let matched = false;
    for (const { pattern } of PY_SQL_INLINE_PATTERNS) {
      if (pattern.test(line)) {
        vulns.push(makeSqlVuln(ctx, i + 1, PY_USER_INPUT.test(line)));
        matched = true;
        break;
      }
    }
    if (matched) continue;

    // Check variable-flow: execute(query) where query is SQL-tainted
    if (/\.execute\s*\(\s*(\w+)\s*[,)]/.test(line)) {
      const varMatch = line.match(/\.execute\s*\(\s*(\w+)\s*[,)]/);
      if (varMatch && sqlTainted.has(varMatch[1])) {
        vulns.push(makeSqlVuln(ctx, i + 1, true));
      }
    }
  }

  return vulns;
}

function makeSqlVuln(ctx: ScanContext, line: number, isTainted: boolean): Vulnerability {
  return {
    ruleId: "VEXLIT-002",
    ruleName: "SQL Injection",
    severity: "critical",
    confidence: isTainted ? "high" : "medium",
    message: isTainted
      ? "SQL injection — dynamic SQL query with user-controlled data"
      : "Potential SQL injection — dynamic SQL query",
    filePath: ctx.filePath,
    line,
    column: 1,
    snippet: ctx.lines[line - 1]?.trim() ?? "",
    cwe: "CWE-89",
    owasp: "A03:2021",
    suggestion: "Use parameterized queries or prepared statements instead of string concatenation.",
  };
}

// ── Rule export ──

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
    if (ctx.language === "python") {
      return scanPySql(ctx);
    }

    // JS/TS detection
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];

      for (const { name, pattern } of SQL_INJECTION_PATTERNS) {
        if (!pattern.test(line)) continue;

        const lineNum = i + 1;

        // AST verification for JS/TS: confirm BinaryExpression or TemplateLiteral
        if (ast) {
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
