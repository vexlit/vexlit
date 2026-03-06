import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";
import type { TreeSitterTree, TreeSitterNode } from "../tree-sitter.js";
import { walkTreeSitter } from "../tree-sitter.js";
import { collectJsSanitizedVars, collectPySanitizedVars, collectPySanitizedVarsRegex, surroundingHasSanitizer } from "../sanitizers.js";

// ── JS/TS detection ──

const PATH_TRAVERSAL_REGEX =
  /(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream|open|access|stat|unlink|rmdir|mkdir)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|`|["'][^"']*["']\s*\+)/;

const PATH_JOIN_REGEX =
  /path\.(?:join|resolve)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/;

const FS_METHODS = new Set([
  "readFile", "readFileSync", "writeFile", "writeFileSync",
  "createReadStream", "createWriteStream", "open", "openSync",
  "access", "accessSync", "stat", "statSync",
  "unlink", "unlinkSync", "rmdir", "rmdirSync", "mkdir", "mkdirSync",
]);

function collectTaintedVarsJS(ast: AST): Set<string> {
  const tainted = new Set<string>();
  walkAST(ast, (node: TSESTree.Node) => {
    if (node.type === "VariableDeclarator" && node.init) {
      if (isUserInputExpression(node.init)) {
        if (node.id.type === "Identifier") tainted.add(node.id.name);
        if (node.id.type === "ObjectPattern") {
          for (const prop of node.id.properties) {
            if (prop.type === "Property" && prop.value.type === "Identifier") {
              tainted.add(prop.value.name);
            }
          }
        }
      }
      // Destructuring: const { file } = req.query
      if (
        node.id.type === "ObjectPattern" &&
        node.init.type === "MemberExpression" &&
        isUserInputExpression(node.init)
      ) {
        for (const prop of node.id.properties) {
          if (prop.type === "Property" && prop.value.type === "Identifier") {
            tainted.add(prop.value.name);
          }
        }
      }
    }
  });
  return tainted;
}

function containsUserInputOrTainted(node: TSESTree.Node, tainted: Set<string>): boolean {
  if (isUserInputExpression(node)) return true;
  if (node.type === "Identifier" && tainted.has(node.name)) return true;
  if (node.type === "BinaryExpression") {
    return containsUserInputOrTainted(node.left, tainted) ||
           containsUserInputOrTainted(node.right, tainted);
  }
  return false;
}

function hasPathTraversalAST(ast: AST, line: number, sanitizedVars: Map<string, Set<string>>): boolean {
  const tainted = collectTaintedVarsJS(ast);
  // Remove sanitized vars from tainted
  for (const [name, cats] of sanitizedVars) {
    if (cats.has("path")) tainted.delete(name);
  }

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
      if (!calleeName) return;

      // fs.readFile(req.query.file) / fs.readFile("/data/" + file) / fs.readFile(file)
      if (FS_METHODS.has(calleeName)) {
        const firstArg = node.arguments[0];
        if (isUserInputExpression(firstArg) || isUnsafeTemplate(firstArg)) {
          found = true;
          return;
        }
        // BinaryExpression with tainted variable: "/data/" + file
        if (firstArg.type === "BinaryExpression" && firstArg.operator === "+") {
          if (containsUserInputOrTainted(firstArg, tainted)) {
            found = true;
            return;
          }
        }
        // Direct tainted variable: readFile(file)
        if (firstArg.type === "Identifier" && tainted.has(firstArg.name)) {
          found = true;
          return;
        }
      }

      // path.join(base, req.params.file) / path.join(base, file)
      if (
        (calleeName === "join" || calleeName === "resolve") &&
        node.callee.type === "MemberExpression" &&
        node.callee.object.type === "Identifier" &&
        node.callee.object.name === "path"
      ) {
        for (const arg of node.arguments) {
          if (isUserInputExpression(arg)) {
            found = true;
            return;
          }
          if (arg.type === "Identifier" && tainted.has(arg.name)) {
            found = true;
            return;
          }
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

function isUserInputExpression(node: TSESTree.Node): boolean {
  if (node.type === "MemberExpression") {
    const src = flattenMember(node);
    return /^(req|request)\.(params|query|body|headers)/.test(src);
  }
  return false;
}

function isUnsafeTemplate(node: TSESTree.Node): boolean {
  return node.type === "TemplateLiteral" && node.expressions.length > 0;
}

function flattenMember(node: TSESTree.MemberExpression): string {
  const prop =
    node.property.type === "Identifier" ? node.property.name : "?";
  if (node.object.type === "Identifier") {
    return `${node.object.name}.${prop}`;
  }
  if (node.object.type === "MemberExpression") {
    return `${flattenMember(node.object)}.${prop}`;
  }
  return prop;
}

// ── Python detection ──

const PY_FILE_FUNCS = new Set(["open"]);
const PY_USER_INPUT = /\b(?:request\.\w+|input\s*\(|sys\.argv)/;

const PY_PATH_TRAVERSAL_REGEX =
  /\bopen\s*\(\s*(?:request\.|f["']|["'][^"']*["']\s*\+)/;

function scanPyPathTraversal(ctx: ScanContext): Vulnerability[] {
  const tree = ctx.treeSitterTree as TreeSitterTree | null;
  if (tree) return scanPyPathTreeSitter(ctx, tree);
  return scanPyPathRegex(ctx);
}

function scanPyPathTreeSitter(ctx: ScanContext, tree: TreeSitterTree): Vulnerability[] {
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

  // Collect sanitized variables (os.path.basename, os.path.realpath, etc.)
  const sanitized = collectPySanitizedVars(tree.rootNode, walkTreeSitter, "path");
  for (const v of sanitized) tainted.delete(v);

  walkTreeSitter(tree.rootNode, (node: TreeSitterNode) => {
    if (node.type !== "call") return;
    const func = node.childForFieldName("function");
    if (!func) return;

    // Match: open(...)
    const funcName = func.type === "identifier" ? func.text : null;
    if (!funcName || !PY_FILE_FUNCS.has(funcName)) return;

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

    if (!isTainted) {
      // Check for concatenation with tainted variable
      if (firstArg.type === "binary_operator" || firstArg.type === "concatenated_string") {
        const hasTaint = firstArg.namedChildren.some((c: TreeSitterNode) => {
          if (c.type === "identifier" && tainted.has(c.text)) return true;
          return c.namedChildren.some((gc: TreeSitterNode) =>
            gc.type === "identifier" && tainted.has(gc.text)
          );
        });
        if (!hasTaint) return;
      } else {
        return;
      }
    }

    vulns.push({
      ruleId: "VEXLIT-021",
      ruleName: "Path Traversal",
      severity: "critical",
      confidence: "high",
      message: "Path traversal — user input flows into file system operation",
      filePath: ctx.filePath,
      line: node.startPosition.row + 1,
      column: 1,
      snippet: ctx.lines[node.startPosition.row]?.trim() ?? "",
      cwe: "CWE-22",
      owasp: "A01:2021",
      suggestion: "Validate and sanitize file paths. Use os.path.realpath() and verify the result stays within allowed boundaries.",
    });
  });

  return vulns;
}

function scanPyPathRegex(ctx: ScanContext): Vulnerability[] {
  const vulns: Vulnerability[] = [];

  // Collect sanitized variables
  const sanitized = collectPySanitizedVarsRegex(ctx.lines, "path");

  // Collect tainted variables
  const tainted = new Set<string>();
  for (const l of ctx.lines) {
    const m = l.match(/^\s*(\w+)\s*=\s*.*\b(?:request\.\w+|input\s*\(|sys\.argv)/);
    if (m && !sanitized.has(m[1])) tainted.add(m[1]);
  }

  for (let i = 0; i < ctx.lines.length; i++) {
    const line = ctx.lines[i];
    if (!/\bopen\s*\(/.test(line)) continue;

    // Safe: open("literal_string")
    if (/\bopen\s*\(\s*["'][^"']*["']\s*[,)]/.test(line)) continue;

    const isTainted =
      PY_USER_INPUT.test(line) ||
      PY_PATH_TRAVERSAL_REGEX.test(line) ||
      [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(line));

    if (!isTainted) continue;

    vulns.push({
      ruleId: "VEXLIT-021",
      ruleName: "Path Traversal",
      severity: "critical",
      confidence: PY_USER_INPUT.test(line) ? "high" : "medium",
      message: "Path traversal — user input in file system operation",
      filePath: ctx.filePath,
      line: i + 1,
      column: 1,
      snippet: line.trim(),
      cwe: "CWE-22",
      owasp: "A01:2021",
      suggestion: "Validate and sanitize file paths. Use os.path.realpath() and verify the result stays within allowed boundaries.",
    });
  }

  return vulns;
}

// ── Rule export ──

export const pathTraversalRule: Rule = {
  id: "VEXLIT-021",
  name: "Path Traversal",
  severity: "critical",
  description: "Unsanitized user input used in file system operations allows directory traversal",
  cwe: "CWE-22",
  owasp: "A01:2021",
  languages: ["javascript", "typescript", "python"],
  suggestion: "Validate and sanitize file paths. Use path.resolve() with a base directory and verify the result stays within allowed boundaries. Never pass user input directly to fs operations.",

  scan(ctx: ScanContext): Vulnerability[] {
    if (ctx.language === "python") {
      return scanPyPathTraversal(ctx);
    }

    // JS/TS detection
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    const sanitizedVars = ast
      ? collectJsSanitizedVars(ast, walkAST as (a: unknown, v: (n: TSESTree.Node) => void) => void)
      : new Map<string, Set<string>>();

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];
      if (!PATH_TRAVERSAL_REGEX.test(line) && !PATH_JOIN_REGEX.test(line)) continue;

      const lineNum = i + 1;

      if (ast) {
        if (!hasPathTraversalAST(ast, lineNum, sanitizedVars)) continue;
      }

      // Lower confidence if path boundary check is nearby
      let confidence: "high" | "medium" | "low" = "high";
      if (surroundingHasSanitizer(ctx.lines, i, "path", ctx.language as "javascript" | "typescript")) {
        confidence = "medium";
      }

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "Path traversal — unsanitized user input in file system operation",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: line.trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
        confidence,
      });
    }
    return vulnerabilities;
  },
};
