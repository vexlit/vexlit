import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";
import type { TreeSitterTree, TreeSitterNode } from "../tree-sitter.js";
import { walkTreeSitter } from "../tree-sitter.js";

// ── JS/TS detection ──

const EVAL_REGEX = /\beval\s*\(\s*[^"'`\d)]/;

function hasUnsafeEvalAtLine(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;

    if (
      node.type === "CallExpression" &&
      node.loc &&
      node.loc.start.line === line &&
      node.callee.type === "Identifier" &&
      node.callee.name === "eval"
    ) {
      if (node.arguments.length > 0 && node.arguments[0].type !== "Literal") {
        found = true;
      }
    }
  });
  return found;
}

// ── Python detection ──

const PY_EVAL_EXEC_REGEX = /\b(?:eval|exec)\s*\(/;
const PY_USER_INPUT = /\b(?:request\.\w+|input\s*\(|sys\.argv)/;

function scanPyEval(ctx: ScanContext): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  const tree = ctx.treeSitterTree as TreeSitterTree | null;

  if (tree) {
    return scanPyEvalTreeSitter(ctx, tree);
  }

  // Regex fallback
  for (let i = 0; i < ctx.lines.length; i++) {
    const line = ctx.lines[i];
    if (!PY_EVAL_EXEC_REGEX.test(line)) continue;

    // Skip: eval() with no dynamic content (pure string literal)
    if (/\b(?:eval|exec)\s*\(\s*["'][^"']*["']\s*[,)]/.test(line)) continue;

    const isTainted = PY_USER_INPUT.test(line);
    vulns.push({
      ruleId: "VEXLIT-023",
      ruleName: "Eval Injection",
      severity: "critical",
      confidence: isTainted ? "high" : "medium",
      message: isTainted
        ? "eval()/exec() with user input — code injection"
        : "eval()/exec() with dynamic input — potential code injection",
      filePath: ctx.filePath,
      line: i + 1,
      column: 1,
      snippet: line.trim(),
      cwe: "CWE-95",
      owasp: "A03:2021",
      suggestion: "Avoid eval()/exec() with dynamic input. Use ast.literal_eval() for safe evaluation of literals.",
    });
  }
  return vulns;
}

function scanPyEvalTreeSitter(ctx: ScanContext, tree: TreeSitterTree): Vulnerability[] {
  const vulns: Vulnerability[] = [];

  // Collect tainted variables
  const tainted = new Set<string>();
  walkTreeSitter(tree.rootNode, (node: TreeSitterNode) => {
    if (node.type !== "assignment") return;
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (!left || !right || left.type !== "identifier") return;
    if (PY_USER_INPUT.test(right.text)) tainted.add(left.text);
  });
  // Transitive
  walkTreeSitter(tree.rootNode, (node: TreeSitterNode) => {
    if (node.type !== "assignment") return;
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (!left || !right || left.type !== "identifier") return;
    if (tainted.has(left.text)) return;
    if (right.namedChildren.some((c: TreeSitterNode) =>
      c.type === "identifier" && tainted.has(c.text)
    )) {
      tainted.add(left.text);
    }
  });

  walkTreeSitter(tree.rootNode, (node: TreeSitterNode) => {
    if (node.type !== "call") return;
    const func = node.childForFieldName("function");
    if (!func || func.type !== "identifier") return;
    if (func.text !== "eval" && func.text !== "exec") return;

    const argsNode = node.childForFieldName("arguments");
    if (!argsNode || argsNode.namedChildren.length === 0) return;

    const firstArg = argsNode.namedChildren[0];

    // Safe: pure string literal with no interpolation
    if (firstArg.type === "string" && firstArg.namedChildren.length === 0) return;

    const isTainted =
      PY_USER_INPUT.test(firstArg.text) ||
      (firstArg.type === "identifier" && tainted.has(firstArg.text)) ||
      firstArg.namedChildren.some((c: TreeSitterNode) =>
        c.type === "identifier" && tainted.has(c.text)
      );

    vulns.push({
      ruleId: "VEXLIT-023",
      ruleName: "Eval Injection",
      severity: "critical",
      confidence: isTainted ? "high" : "medium",
      message: isTainted
        ? "eval()/exec() with user input — code injection"
        : "eval()/exec() with dynamic input — potential code injection",
      filePath: ctx.filePath,
      line: node.startPosition.row + 1,
      column: 1,
      snippet: ctx.lines[node.startPosition.row]?.trim() ?? "",
      cwe: "CWE-95",
      owasp: "A03:2021",
      suggestion: "Avoid eval()/exec() with dynamic input. Use ast.literal_eval() for safe evaluation of literals.",
    });
  });

  return vulns;
}

// ── Rule export ──

export const evalInjectionRule: Rule = {
  id: "VEXLIT-023",
  name: "Eval Injection",
  severity: "critical",
  description: "Dynamic code execution via eval()/exec() with non-static input",
  cwe: "CWE-95",
  owasp: "A03:2021",
  languages: ["javascript", "typescript", "python"],
  suggestion: "Avoid eval() with dynamic input. Use JSON.parse(), predefined functions, or a sandboxed evaluator instead.",

  scan(ctx: ScanContext): Vulnerability[] {
    if (ctx.language === "python") {
      return scanPyEval(ctx);
    }

    // JS/TS detection
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      if (!EVAL_REGEX.test(ctx.lines[i])) continue;
      const lineNum = i + 1;

      if (ast && !hasUnsafeEvalAtLine(ast, lineNum)) continue;

      vulnerabilities.push({
        ruleId: this.id,
        ruleName: this.name,
        severity: this.severity,
        message: "eval() with dynamic input — code injection risk",
        filePath: ctx.filePath,
        line: lineNum,
        column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe,
        owasp: this.owasp,
        suggestion: this.suggestion,
          confidence: "high",
      });
    }
    return vulnerabilities;
  },
};
