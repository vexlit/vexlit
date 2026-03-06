import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";
import type { TreeSitterTree, TreeSitterNode } from "../tree-sitter.js";
import { walkTreeSitter } from "../tree-sitter.js";

const SSRF_REGEX =
  /(?:fetch|axios\.get|axios\.post|axios\(|http\.get|http\.request|https\.get|https\.request|got\(|request\()\s*\(\s*(?:req\.|request\.|query\.|params\.|body\.|`|\w)/;

const HTTP_CALLEES = new Set([
  "fetch", "get", "post", "put", "patch", "delete", "request",
]);

function hasSsrfAST(ast: AST, line: number): boolean {
  // First pass: collect variable names assigned from user input
  const taintedVars = new Set<string>();
  walkAST(ast, (node: TSESTree.Node) => {
    // const { url } = req.query  OR  const url = req.query.url
    if (
      node.type === "VariableDeclarator" &&
      node.init
    ) {
      if (isUserInput(node.init)) {
        if (node.id.type === "Identifier") taintedVars.add(node.id.name);
        if (node.id.type === "ObjectPattern") {
          for (const prop of node.id.properties) {
            if (prop.type === "Property" && prop.value.type === "Identifier") {
              taintedVars.add(prop.value.name);
            }
          }
        }
      }
      // Destructuring: const { url } = req.query
      if (
        node.id.type === "ObjectPattern" &&
        node.init.type === "MemberExpression" &&
        isUserInput(node.init)
      ) {
        for (const prop of node.id.properties) {
          if (prop.type === "Property" && prop.value.type === "Identifier") {
            taintedVars.add(prop.value.name);
          }
        }
      }
    }
  });

  // Second pass: check HTTP calls at the target line
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
      if (calleeName && HTTP_CALLEES.has(calleeName)) {
        const firstArg = node.arguments[0];
        // Direct user input: fetch(req.query.url)
        if (isUserInput(firstArg)) {
          found = true;
          return;
        }
        // Indirect via tainted variable: fetch(url) where url came from req.query
        if (firstArg.type === "Identifier" && taintedVars.has(firstArg.name)) {
          found = true;
          return;
        }
        // Template literal with user input or tainted var
        if (firstArg.type === "TemplateLiteral" && firstArg.expressions.length > 0) {
          for (const expr of firstArg.expressions) {
            if (isUserInput(expr)) {
              found = true;
              return;
            }
            if (expr.type === "Identifier" && taintedVars.has(expr.name)) {
              found = true;
              return;
            }
          }
        }
      }
    }
  });
  return found;
}

function getCalleeName(callee: TSESTree.Node): string | null {
  if (callee.type === "Identifier") return callee.name;
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier")
    return callee.property.name;
  return null;
}

function isUserInput(node: TSESTree.Node): boolean {
  if (node.type === "MemberExpression") {
    const src = flattenMember(node);
    return /^(req|request)\.(body|query|params|headers)/.test(src);
  }
  return false;
}

function flattenMember(node: TSESTree.MemberExpression): string {
  const prop = node.property.type === "Identifier" ? node.property.name : "?";
  if (node.object.type === "Identifier") return `${node.object.name}.${prop}`;
  if (node.object.type === "MemberExpression") return `${flattenMember(node.object)}.${prop}`;
  return prop;
}

// ── Python detection ──

const PY_HTTP_FUNCS = new Map<string, Set<string>>([
  ["requests", new Set(["get", "post", "put", "patch", "delete", "head", "options", "request"])],
  ["urllib", new Set(["urlopen"])],
  ["urllib.request", new Set(["urlopen", "urlretrieve"])],
  ["httpx", new Set(["get", "post", "put", "patch", "delete", "head", "options", "request"])],
]);

const PY_SSRF_BASELINE =
  /\b(?:requests\.(?:get|post|put|patch|delete|head|options|request)|urllib\.(?:request\.)?(?:urlopen|urlretrieve)|httpx\.(?:get|post|put|patch|delete|head|options|request))\s*\(/;

const PY_USER_INPUT = /\b(?:request\.\w+|input\s*\(|sys\.argv)/;

function scanPySsrf(ctx: ScanContext): Vulnerability[] {
  const tree = ctx.treeSitterTree as TreeSitterTree | null;
  if (tree) return scanPySsrfTreeSitter(ctx, tree);
  return scanPySsrfRegex(ctx);
}

function scanPySsrfTreeSitter(ctx: ScanContext, tree: TreeSitterTree): Vulnerability[] {
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
    if (!func || func.type !== "attribute") return;

    const obj = func.childForFieldName("object");
    const attr = func.childForFieldName("attribute");
    if (!obj || !attr) return;

    // Match module.method patterns
    const objText = obj.text;
    const attrText = attr.text;
    let matched = false;
    for (const [mod, methods] of PY_HTTP_FUNCS) {
      if (objText === mod && methods.has(attrText)) { matched = true; break; }
      // Handle urllib.request.urlopen (obj = urllib.request)
      if (obj.type === "attribute" && `${obj.text}` === mod && methods.has(attrText)) { matched = true; break; }
    }
    if (!matched) return;

    const argsNode = node.childForFieldName("arguments");
    if (!argsNode || argsNode.namedChildren.length === 0) return;

    const firstArg = argsNode.namedChildren[0];

    // Safe: pure string literal
    if (firstArg.type === "string" && !firstArg.namedChildren.some((c: TreeSitterNode) => c.type === "interpolation")) return;

    const isTainted =
      PY_USER_INPUT.test(firstArg.text) ||
      (firstArg.type === "identifier" && tainted.has(firstArg.text)) ||
      firstArg.namedChildren.some((c: TreeSitterNode) =>
        c.type === "identifier" && tainted.has(c.text)
      );

    vulns.push({
      ruleId: "VEXLIT-012",
      ruleName: "Server-Side Request Forgery (SSRF)",
      severity: "critical",
      confidence: isTainted ? "high" : "medium",
      message: isTainted
        ? "SSRF — user input flows into HTTP request URL"
        : "SSRF — dynamic URL in HTTP request",
      filePath: ctx.filePath,
      line: node.startPosition.row + 1,
      column: 1,
      snippet: ctx.lines[node.startPosition.row]?.trim() ?? "",
      cwe: "CWE-918",
      owasp: "A10:2021",
      suggestion: "Validate and sanitize URLs. Use an allowlist of permitted domains. Block internal/private IP ranges.",
    });
  });

  return vulns;
}

function scanPySsrfRegex(ctx: ScanContext): Vulnerability[] {
  const vulns: Vulnerability[] = [];

  // Collect tainted vars
  const tainted = new Set<string>();
  for (const l of ctx.lines) {
    const m = l.match(/^\s*(\w+)\s*=\s*.*\b(?:request\.\w+|input\s*\(|sys\.argv)/);
    if (m) tainted.add(m[1]);
  }

  for (let i = 0; i < ctx.lines.length; i++) {
    const line = ctx.lines[i];
    if (!PY_SSRF_BASELINE.test(line)) continue;

    // Safe: first argument is a plain string literal
    if (/\(\s*["'][^"']*["']\s*[,)]/.test(line)) continue;

    const isTainted =
      PY_USER_INPUT.test(line) ||
      [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(line));

    vulns.push({
      ruleId: "VEXLIT-012",
      ruleName: "Server-Side Request Forgery (SSRF)",
      severity: "critical",
      confidence: isTainted ? "high" : "medium",
      message: isTainted
        ? "SSRF — user input flows into HTTP request URL"
        : "SSRF — dynamic URL in HTTP request",
      filePath: ctx.filePath,
      line: i + 1,
      column: 1,
      snippet: line.trim(),
      cwe: "CWE-918",
      owasp: "A10:2021",
      suggestion: "Validate and sanitize URLs. Use an allowlist of permitted domains. Block internal/private IP ranges.",
    });
  }

  return vulns;
}

// ── Rule export ──

export const ssrfRule: Rule = {
  id: "VEXLIT-012",
  name: "Server-Side Request Forgery (SSRF)",
  severity: "critical",
  description: "User-controlled URL passed to server-side HTTP request",
  cwe: "CWE-918",
  owasp: "A10:2021",
  languages: ["javascript", "typescript", "python"],
  suggestion: "Validate and sanitize URLs. Use an allowlist of permitted domains. Block internal/private IP ranges.",

  scan(ctx: ScanContext): Vulnerability[] {
    if (ctx.language === "python") {
      return scanPySsrf(ctx);
    }

    // JS/TS detection
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      if (!SSRF_REGEX.test(ctx.lines[i])) continue;
      const lineNum = i + 1;

      if (ast && !hasSsrfAST(ast, lineNum)) continue;

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "SSRF — user-controlled URL in server-side HTTP request",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: ctx.lines[i].trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
          confidence: "high",
      });
    }
    return vulnerabilities;
  },
};
