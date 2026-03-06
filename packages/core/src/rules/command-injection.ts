import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";
import type { TreeSitterTree, TreeSitterNode } from "../tree-sitter.js";
import { walkTreeSitter } from "../tree-sitter.js";
import { collectJsSanitizedVars, isJsSanitizerCall, surroundingHasSanitizer } from "../sanitizers.js";
import { isJsUserInput, containsJsUserInput, PY_USER_INPUT } from "../sources.js";

// ── JS/TS detection ──

const CMD_INJECTION_REGEX =
  /(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|`|["'][^"']*["']\s*\+)/;

const SHELL_EXEC_METHODS = new Set([
  "exec", "execSync", "execFile", "execFileSync",
  "spawn", "spawnSync", "fork",
]);

function hasCommandInjectionAST(ast: AST, line: number, sanitizedVars: Map<string, Set<string>>): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    if (
      node.type === "CallExpression" &&
      node.loc &&
      node.loc.start.line === line &&
      node.arguments.length > 0
    ) {
      const calleeName = getCalleeName(node.callee);
      if (!calleeName || !SHELL_EXEC_METHODS.has(calleeName)) return;

      // Safe: execFile/spawn with array arguments (no shell injection)
      if ((calleeName === "execFile" || calleeName === "execFileSync" ||
           calleeName === "spawn" || calleeName === "spawnSync") &&
          node.arguments.length >= 2 && node.arguments[1].type === "ArrayExpression") {
        return;
      }

      const firstArg = node.arguments[0];

      if (firstArg.type === "TemplateLiteral" && firstArg.expressions.length > 0) {
        // Safe if all interpolated expressions are sanitized
        const allSafe = firstArg.expressions.every((expr) =>
          isJsSanitizerCall(expr, "cmd") ||
          (expr.type === "Identifier" && sanitizedVars.get(expr.name)?.has("cmd"))
        );
        if (!allSafe) found = true;
        return;
      }

      if (isJsUserInput(firstArg)) {
        found = true;
        return;
      }

      // Safe: sanitized variable
      if (firstArg.type === "Identifier" && sanitizedVars.get(firstArg.name)?.has("cmd")) return;

      if (firstArg.type === "BinaryExpression" && firstArg.operator === "+") {
        if (containsJsUserInput(firstArg)) {
          found = true;
          return;
        }
      }
    }
  });
  return found;
}

function getCalleeName(callee: TSESTree.Node): string | null {
  if (callee.type === "Identifier") return callee.name;
  if (
    callee.type === "MemberExpression" &&
    callee.property.type === "Identifier"
  ) {
    return callee.property.name;
  }
  return null;
}


// ── Python detection ──

const PYTHON_DANGEROUS_FUNCS = new Map<string, Set<string>>([
  ["os", new Set(["system", "popen"])],
  ["subprocess", new Set(["call", "run", "Popen", "check_output", "check_call"])],
]);

const PYTHON_CMD_BASELINE =
  /\b(?:os\.(?:system|popen)|subprocess\.(?:call|run|Popen|check_output|check_call))\s*\(/;

/** Known Python sanitizer functions that neutralize command injection */
const PYTHON_SANITIZERS = new Set([
  "shlex.quote",
  "quote",        // from shlex import quote
  "pipes.quote",
]);

/** Check if a tree-sitter node is a safe (non-injectable) argument */
function isPySafeArg(node: TreeSitterNode, sanitized: Set<string>): boolean {
  // Pure string literal: "hardcoded"
  if (node.type === "string") {
    return !node.namedChildren.some((c) => c.type === "interpolation");
  }
  // List argument: subprocess.run(["echo", user_input]) — no shell injection
  if (node.type === "list") return true;
  // Variable that passed through a sanitizer
  if (node.type === "identifier" && sanitized.has(node.text)) return true;
  // Direct sanitizer call: os.system(shlex.quote(x))
  if (isPySanitizerCall(node)) return true;
  return false;
}

/** Check if a tree-sitter node contains tainted data */
function isPyTainted(node: TreeSitterNode, tainted: Set<string>): boolean {
  if (node.type === "identifier") return tainted.has(node.text);
  if (PY_USER_INPUT.test(node.text)) return true;
  if (node.type === "binary_operator" || node.type === "concatenated_string") {
    return node.namedChildren.some((c) => isPyTainted(c, tainted));
  }
  // f-string interpolation: f"echo {user_input}"
  if (node.type === "string" || node.type === "interpolation") {
    return node.namedChildren.some((c) => isPyTainted(c, tainted));
  }
  // Call expression: request.args.get("host")
  if (node.type === "call") {
    return PY_USER_INPUT.test(node.text);
  }
  return false;
}

/** Check if a tree-sitter node references any tainted variable */
function containsTaintedRef(node: TreeSitterNode, tainted: Set<string>): boolean {
  if (node.type === "identifier" && tainted.has(node.text)) return true;
  return node.namedChildren.some((c) => containsTaintedRef(c, tainted));
}

/** Check if a tree-sitter node is a call to a known sanitizer (e.g. shlex.quote) */
function isPySanitizerCall(node: TreeSitterNode): boolean {
  if (node.type !== "call") return false;
  const func = node.childForFieldName("function");
  if (!func) return false;
  // shlex.quote(x) → attribute node
  if (func.type === "attribute") {
    const obj = func.childForFieldName("object");
    const attr = func.childForFieldName("attribute");
    if (obj && attr) {
      const fullName = `${obj.text}.${attr.text}`;
      if (PYTHON_SANITIZERS.has(fullName)) return true;
    }
  }
  // quote(x) → identifier node (from shlex import quote)
  if (func.type === "identifier" && PYTHON_SANITIZERS.has(func.text)) return true;
  return false;
}

/** Collect tainted and sanitized variable sets */
function collectPyTaintState(tree: TreeSitterTree): { tainted: Set<string>; sanitized: Set<string> } {
  const tainted = new Set<string>();
  const sanitized = new Set<string>();

  // Pass 1: direct user input sources
  walkTreeSitter(tree.rootNode, (node) => {
    if (node.type !== "assignment") return;
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (!left || !right || left.type !== "identifier") return;
    if (PY_USER_INPUT.test(right.text)) {
      tainted.add(left.text);
    }
  });

  // Pass 2: transitive — variables derived from tainted vars
  walkTreeSitter(tree.rootNode, (node) => {
    if (node.type !== "assignment") return;
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (!left || !right || left.type !== "identifier") return;
    if (tainted.has(left.text)) return;
    if (containsTaintedRef(right, tainted)) {
      tainted.add(left.text);
    }
  });

  // Pass 3: variables that pass through a sanitizer are safe
  // e.g. safe = shlex.quote(cmd) → "safe" is sanitized
  walkTreeSitter(tree.rootNode, (node) => {
    if (node.type !== "assignment") return;
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (!left || !right || left.type !== "identifier") return;
    if (isPySanitizerCall(right)) {
      tainted.delete(left.text);
      sanitized.add(left.text);
    }
  });

  return { tainted, sanitized };
}

/** Check if a binary expression like "echo " + safe has no tainted leaves */
function isBinaryAllSanitized(node: TreeSitterNode, tainted: Set<string>, sanitized: Set<string>): boolean {
  if (node.type !== "binary_operator") return false;
  // If the expression contains direct user input patterns, it's not safe
  if (PY_USER_INPUT.test(node.text)) return false;
  // All identifier leaves must be either sanitized or not tainted
  const identifiers: TreeSitterNode[] = [];
  function collectIds(n: TreeSitterNode) {
    if (n.type === "identifier") { identifiers.push(n); return; }
    for (const c of n.namedChildren) collectIds(c);
  }
  collectIds(node);
  // If any identifier is tainted (and not sanitized), it's not safe
  return identifiers.every((id) => sanitized.has(id.text) || !tainted.has(id.text));
}

function makePyVuln(
  ctx: ScanContext,
  line: number,
  isTainted: boolean,
): Vulnerability {
  return {
    ruleId: "VEXLIT-022",
    ruleName: "Command Injection",
    severity: isTainted ? "critical" : "warning",
    confidence: isTainted ? "high" : "medium",
    message: isTainted
      ? "Command injection — user input flows into shell command"
      : "Potential command injection — dynamic value in shell command",
    filePath: ctx.filePath,
    line,
    column: 1,
    snippet: ctx.lines[line - 1]?.trim() ?? "",
    cwe: "CWE-78",
    owasp: "A03:2021",
    suggestion:
      "Never pass user input to shell commands. Use subprocess with argument arrays instead of shell=True. Validate and sanitize all inputs.",
  };
}

/** Scan Python using tree-sitter AST */
function scanPyTreeSitter(ctx: ScanContext): Vulnerability[] {
  const tree = ctx.treeSitterTree as TreeSitterTree;
  const { tainted, sanitized } = collectPyTaintState(tree);
  const vulns: Vulnerability[] = [];

  walkTreeSitter(tree.rootNode, (node) => {
    if (node.type !== "call") return;

    const func = node.childForFieldName("function");
    if (!func || func.type !== "attribute") return;

    const obj = func.childForFieldName("object");
    const attr = func.childForFieldName("attribute");
    if (!obj || !attr || obj.type !== "identifier") return;

    const methods = PYTHON_DANGEROUS_FUNCS.get(obj.text);
    if (!methods || !methods.has(attr.text)) return;

    const argsNode = node.childForFieldName("arguments");
    if (!argsNode || argsNode.namedChildren.length === 0) return;

    const firstArg = argsNode.namedChildren[0];
    if (isPySafeArg(firstArg, sanitized)) return;

    // Check if the entire expression is sanitized (e.g. "echo " + sanitized_var)
    if (isBinaryAllSanitized(firstArg, tainted, sanitized)) return;

    const isTainted = isPyTainted(firstArg, tainted);
    vulns.push(makePyVuln(ctx, node.startPosition.row + 1, isTainted));
  });

  return vulns;
}

/** Regex fallback for Python when tree-sitter is unavailable */
function scanPyRegex(ctx: ScanContext): Vulnerability[] {
  const vulns: Vulnerability[] = [];

  // Collect tainted variable names
  const tainted = new Set<string>();
  for (const l of ctx.lines) {
    const m = l.match(/^\s*(\w+)\s*=\s*.*\b(?:request\.\w+|input\s*\(|sys\.argv)/);
    if (m) tainted.add(m[1]);
  }
  // Transitive: variables derived from tainted vars
  for (const l of ctx.lines) {
    const m = l.match(/^\s*(\w+)\s*=/);
    if (!m || tainted.has(m[1])) continue;
    const rhs = l.slice(l.indexOf("=") + 1);
    for (const v of tainted) {
      if (new RegExp(`\\b${v}\\b`).test(rhs)) {
        tainted.add(m[1]);
        break;
      }
    }
  }
  // Collect sanitized variables: x = shlex.quote(y) → x is safe
  const sanitized = new Set<string>();
  for (const l of ctx.lines) {
    const m = l.match(/^\s*(\w+)\s*=\s*(?:shlex\.quote|pipes\.quote|quote)\s*\(/);
    if (m) {
      tainted.delete(m[1]);
      sanitized.add(m[1]);
    }
  }

  for (let i = 0; i < ctx.lines.length; i++) {
    const line = ctx.lines[i];
    if (!PYTHON_CMD_BASELINE.test(line)) continue;

    // Safe: first argument is a list literal (no shell injection possible)
    if (/\(\s*\[/.test(line)) continue;
    // Safe: first argument is a plain string literal (no concatenation or f-string)
    if (/\(\s*["'][^"']*["']\s*[,)]/.test(line)) continue;
    // Safe: first argument is a sanitized variable
    if ([...sanitized].some((v) => new RegExp(`\\(\\s*${v}\\b`).test(line))) continue;
    // Safe: all variables on the line are sanitized (e.g. "echo " + safe)
    if ([...sanitized].some((v) => new RegExp(`\\b${v}\\b`).test(line)) &&
        ![...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(line))) continue;

    const isTainted =
      PY_USER_INPUT.test(line) ||
      [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(line));

    vulns.push(makePyVuln(ctx, i + 1, isTainted));
  }

  return vulns;
}

function scanPython(ctx: ScanContext): Vulnerability[] {
  if (ctx.treeSitterTree) return scanPyTreeSitter(ctx);
  return scanPyRegex(ctx);
}

// ── Rule export ──

export const commandInjectionRule: Rule = {
  id: "VEXLIT-022",
  name: "Command Injection",
  severity: "critical",
  description: "Unsanitized user input passed to shell execution functions",
  cwe: "CWE-78",
  owasp: "A03:2021",
  languages: ["javascript", "typescript", "python"],
  suggestion: "Never pass user input to shell commands. Use execFile/spawn with argument arrays instead of exec. Validate and sanitize all inputs against an allowlist.",

  scan(ctx: ScanContext): Vulnerability[] {
    if (ctx.language === "python") {
      return scanPython(ctx);
    }

    // JS/TS: existing AST-based detection
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    const sanitizedVars = ast
      ? collectJsSanitizedVars(ast, walkAST as (a: unknown, v: (n: TSESTree.Node) => void) => void)
      : new Map<string, Set<string>>();

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];
      if (!CMD_INJECTION_REGEX.test(line)) continue;

      const lineNum = i + 1;

      if (ast) {
        if (!hasCommandInjectionAST(ast, lineNum, sanitizedVars)) continue;
      }

      let confidence: "high" | "medium" | "low" = "high";
      if (surroundingHasSanitizer(ctx.lines, i, "cmd", ctx.language as "javascript" | "typescript")) {
        confidence = "medium";
      }

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "Command injection — unsanitized user input in shell command",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: line.trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
        confidence,
      });
    }
    return vulnerabilities;
  },
};
