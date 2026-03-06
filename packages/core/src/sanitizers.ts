/**
 * Shared sanitizer awareness for SAST rules.
 *
 * Detects when a value has been passed through a known sanitization function,
 * allowing rules to reduce false positives.
 */

import type { TSESTree } from "@typescript-eslint/typescript-estree";
import type { TreeSitterNode } from "./tree-sitter.js";

// ── JS/TS Sanitizer Registry ──

export type SanitizerCategory = "xss" | "sql" | "cmd" | "path" | "ssrf" | "eval" | "universal";

interface JsSanitizer {
  /** Full member expression or function name, e.g. "DOMPurify.sanitize" or "encodeURIComponent" */
  name: string;
  categories: SanitizerCategory[];
}

const JS_SANITIZERS: JsSanitizer[] = [
  // XSS sanitizers
  { name: "DOMPurify.sanitize", categories: ["xss"] },
  { name: "sanitizeHtml", categories: ["xss"] },
  { name: "xss", categories: ["xss"] },
  { name: "escapeHtml", categories: ["xss"] },
  { name: "escape", categories: ["xss"] },

  // Encoding functions (XSS + SSRF)
  { name: "encodeURIComponent", categories: ["xss", "ssrf"] },
  { name: "encodeURI", categories: ["ssrf"] },

  // Validation libraries
  { name: "validator.escape", categories: ["xss"] },
  { name: "validator.isURL", categories: ["ssrf"] },
  { name: "validator.isEmail", categories: ["universal"] },
  { name: "validator.isInt", categories: ["sql", "cmd", "path"] },
  { name: "validator.isNumeric", categories: ["sql", "cmd", "path"] },

  // Number coercion (safe for injection if used with validation)
  { name: "parseInt", categories: ["sql", "cmd", "path", "ssrf"] },
  { name: "parseFloat", categories: ["sql", "cmd", "path", "ssrf"] },
  { name: "Number", categories: ["sql", "cmd", "path", "ssrf"] },

  // Schema validation
  { name: "zod.parse", categories: ["universal"] },
  { name: "Joi.validate", categories: ["universal"] },

  // Path sanitizers
  { name: "path.basename", categories: ["path"] },
  { name: "path.normalize", categories: ["path"] },

  // SQL sanitizers
  { name: "escape", categories: ["sql"] },
  { name: "mysql.escape", categories: ["sql"] },
  { name: "sqlstring.escape", categories: ["sql"] },

  // Command sanitizers
  { name: "shellEscape", categories: ["cmd"] },
];

// Build lookup sets per category
const JS_SANITIZER_NAMES = new Set(JS_SANITIZERS.map((s) => s.name));
const JS_SANITIZERS_BY_CATEGORY = new Map<SanitizerCategory, Set<string>>();
for (const s of JS_SANITIZERS) {
  for (const cat of s.categories) {
    let set = JS_SANITIZERS_BY_CATEGORY.get(cat);
    if (!set) { set = new Set(); JS_SANITIZERS_BY_CATEGORY.set(cat, set); }
    set.add(s.name);
  }
}

/** Flatten a TSESTree MemberExpression to "a.b.c" */
function flattenJsMember(node: TSESTree.MemberExpression): string {
  const prop = node.property.type === "Identifier" ? node.property.name : "?";
  if (node.object.type === "Identifier") return `${node.object.name}.${prop}`;
  if (node.object.type === "MemberExpression") return `${flattenJsMember(node.object)}.${prop}`;
  return prop;
}

/** Get the name of a call expression callee */
function getCallName(node: TSESTree.Node): string | null {
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") return flattenJsMember(node);
  return null;
}

/**
 * Check if a JS/TS AST node is a call to a known sanitizer for the given category.
 * e.g. DOMPurify.sanitize(x), parseInt(x), encodeURIComponent(x)
 */
export function isJsSanitizerCall(node: TSESTree.Node, category: SanitizerCategory): boolean {
  if (node.type !== "CallExpression") return false;
  const name = getCallName(node.callee);
  if (!name) return false;

  const catSet = JS_SANITIZERS_BY_CATEGORY.get(category);
  const uniSet = JS_SANITIZERS_BY_CATEGORY.get("universal");
  return !!(catSet?.has(name) || uniSet?.has(name));
}

/**
 * Check if the right-hand side of an assignment is sanitized (JS/TS).
 * Handles: const safe = DOMPurify.sanitize(input)
 *          const safe = parseInt(input)
 *          const safe = Number(input)
 */
export function isJsSanitizedValue(node: TSESTree.Node, category: SanitizerCategory): boolean {
  return isJsSanitizerCall(node, category);
}

/**
 * Check if a JS/TS AST node has a numeric validation guard in surrounding context.
 * Detects patterns like: if (isNaN(x)) return; / if (!isFinite(x)) return;
 * This is used to detect safe parseInt/Number usage.
 */
export function hasJsNumericGuard(lines: string[], lineIndex: number): boolean {
  const start = Math.max(0, lineIndex - 5);
  const end = Math.min(lines.length, lineIndex + 2);
  const context = lines.slice(start, end).join(" ");
  return /\bisNaN\s*\(/.test(context) || /\bisFinite\s*\(/.test(context) || /\bNumber\.isFinite\s*\(/.test(context) || /\bNumber\.isNaN\s*\(/.test(context);
}

/**
 * Collect JS/TS variables that have been sanitized.
 * Returns a Map from variable name to the set of categories it's sanitized for.
 */
export function collectJsSanitizedVars(
  ast: unknown,
  walkFn: (ast: unknown, visitor: (node: TSESTree.Node) => void) => void,
): Map<string, Set<SanitizerCategory>> {
  const result = new Map<string, Set<SanitizerCategory>>();

  walkFn(ast, (node: TSESTree.Node) => {
    if (node.type !== "VariableDeclarator" || !node.init) return;
    if (node.id.type !== "Identifier") return;

    if (node.init.type === "CallExpression") {
      const name = getCallName(node.init.callee);
      if (!name) return;

      for (const s of JS_SANITIZERS) {
        if (s.name === name) {
          let cats = result.get(node.id.name);
          if (!cats) { cats = new Set(); result.set(node.id.name, cats); }
          for (const c of s.categories) cats.add(c);
        }
      }
    }
  });

  return result;
}

// ── Python Sanitizer Registry ──

interface PySanitizer {
  /** Function call patterns: "html.escape", "markupsafe.escape", "int", etc. */
  names: string[];
  categories: SanitizerCategory[];
}

const PY_SANITIZERS: PySanitizer[] = [
  // XSS
  { names: ["html.escape", "markupsafe.escape", "markupsafe.Markup", "bleach.clean", "escape"], categories: ["xss"] },
  // SQL
  { names: ["int", "float"], categories: ["sql", "cmd", "path", "ssrf"] },
  // Command
  { names: ["shlex.quote", "pipes.quote", "quote"], categories: ["cmd"] },
  // Path
  { names: ["os.path.basename", "os.path.realpath", "os.path.abspath"], categories: ["path"] },
  // URL
  { names: ["urllib.parse.quote", "urllib.parse.quote_plus"], categories: ["ssrf"] },
  // Eval
  { names: ["ast.literal_eval"], categories: ["eval"] },
];

const PY_SANITIZER_NAMES_BY_CAT = new Map<SanitizerCategory, Set<string>>();
for (const s of PY_SANITIZERS) {
  for (const cat of s.categories) {
    let set = PY_SANITIZER_NAMES_BY_CAT.get(cat);
    if (!set) { set = new Set(); PY_SANITIZER_NAMES_BY_CAT.set(cat, set); }
    for (const n of s.names) set.add(n);
  }
}

/** Get the full function name from a tree-sitter call node */
function getPyCallName(node: TreeSitterNode): string | null {
  const func = node.childForFieldName("function");
  if (!func) return null;
  if (func.type === "identifier") return func.text;
  if (func.type === "attribute") {
    const obj = func.childForFieldName("object");
    const attr = func.childForFieldName("attribute");
    if (obj && attr) return `${obj.text}.${attr.text}`;
  }
  return null;
}

/**
 * Check if a tree-sitter call node is a known Python sanitizer for the category.
 */
export function isPySanitizerCallForCategory(node: TreeSitterNode, category: SanitizerCategory): boolean {
  if (node.type !== "call") return false;
  const name = getPyCallName(node);
  if (!name) return false;
  const catSet = PY_SANITIZER_NAMES_BY_CAT.get(category);
  return !!catSet?.has(name);
}

/**
 * Collect Python variables that have been sanitized (tree-sitter).
 * e.g. safe_val = html.escape(user_input)
 *      safe_id = int(request.args.get("id"))
 */
export function collectPySanitizedVars(
  rootNode: TreeSitterNode,
  walkFn: (node: TreeSitterNode, visitor: (n: TreeSitterNode) => void) => void,
  category: SanitizerCategory,
): Set<string> {
  const sanitized = new Set<string>();

  walkFn(rootNode, (node: TreeSitterNode) => {
    if (node.type !== "assignment") return;
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (!left || !right || left.type !== "identifier") return;

    if (isPySanitizerCallForCategory(right, category)) {
      sanitized.add(left.text);
    }
  });

  return sanitized;
}

/**
 * Check if a Python line contains a known sanitizer call for the category (regex fallback).
 */
export function pyLineHasSanitizer(line: string, category: SanitizerCategory): boolean {
  const catSet = PY_SANITIZER_NAMES_BY_CAT.get(category);
  if (!catSet) return false;
  for (const name of catSet) {
    // Match: sanitizer_name(
    const escaped = name.replace(/\./g, "\\.");
    if (new RegExp(`\\b${escaped}\\s*\\(`).test(line)) return true;
  }
  return false;
}

/**
 * Regex-based: collect Python variables assigned from sanitizer calls.
 */
export function collectPySanitizedVarsRegex(lines: string[], category: SanitizerCategory): Set<string> {
  const sanitized = new Set<string>();
  const catSet = PY_SANITIZER_NAMES_BY_CAT.get(category);
  if (!catSet) return sanitized;

  for (const line of lines) {
    const m = line.match(/^\s*(\w+)\s*=\s*/);
    if (!m) continue;
    const rhs = line.slice(line.indexOf("=") + 1);
    for (const name of catSet) {
      const escaped = name.replace(/\./g, "\\.");
      if (new RegExp(`\\b${escaped}\\s*\\(`).test(rhs)) {
        sanitized.add(m[1]);
        break;
      }
    }
  }

  return sanitized;
}

// ── JS/TS Regex helpers ──

/**
 * Check if a JS/TS line contains a known sanitizer call (regex fallback for non-AST mode).
 */
export function jsLineHasSanitizer(line: string, category: SanitizerCategory): boolean {
  const catSet = JS_SANITIZERS_BY_CATEGORY.get(category);
  const uniSet = JS_SANITIZERS_BY_CATEGORY.get("universal");
  const allNames = new Set([...(catSet ?? []), ...(uniSet ?? [])]);

  for (const name of allNames) {
    const escaped = name.replace(/\./g, "\\.");
    if (new RegExp(`\\b${escaped}\\s*\\(`).test(line)) return true;
  }
  return false;
}

/**
 * Check if the surrounding context (±3 lines) contains sanitizer usage for the category.
 */
export function surroundingHasSanitizer(
  lines: string[],
  lineIndex: number,
  category: SanitizerCategory,
  language: "javascript" | "typescript" | "python",
): boolean {
  const start = Math.max(0, lineIndex - 5);
  const end = Math.min(lines.length, lineIndex + 3);

  const checker = language === "python" ? pyLineHasSanitizer : jsLineHasSanitizer;
  for (let i = start; i < end; i++) {
    if (checker(lines[i], category)) return true;
  }
  return false;
}
