/**
 * Centralized user input source registry for SAST rules.
 *
 * Replaces scattered isUserInputExpression / PY_USER_INPUT / flattenMember
 * patterns across individual rule files with a single shared module.
 */

import type { TSESTree } from "@typescript-eslint/typescript-estree";
import type { TreeSitterNode } from "./tree-sitter.js";

// ── JS/TS User Input Sources ──

/** Regex to test a flattened member-expression string for user input */
const JS_USER_INPUT_REGEX = /^(req|request)\.(params|query|body|headers)/;

/** Flatten a TSESTree MemberExpression to "a.b.c" */
export function flattenJsMember(node: TSESTree.MemberExpression): string {
  const prop = node.property.type === "Identifier" ? node.property.name : "?";
  if (node.object.type === "Identifier") return `${node.object.name}.${prop}`;
  if (node.object.type === "MemberExpression") return `${flattenJsMember(node.object)}.${prop}`;
  return prop;
}

/**
 * Check if a TSESTree node is a user input expression.
 * Matches: req.body, req.query, req.params, req.headers (and deeper access like req.body.name)
 */
export function isJsUserInput(node: TSESTree.Node): boolean {
  if (node.type === "MemberExpression") {
    const src = flattenJsMember(node);
    return JS_USER_INPUT_REGEX.test(src);
  }
  return false;
}

/** Recursively check if a node or its BinaryExpression children contain user input */
export function containsJsUserInput(node: TSESTree.Node): boolean {
  if (isJsUserInput(node)) return true;
  if (node.type === "BinaryExpression") {
    return containsJsUserInput(node.left) || containsJsUserInput(node.right);
  }
  return false;
}

/** Check if a node contains user input or references a tainted variable */
export function containsJsUserInputOrTainted(node: TSESTree.Node, tainted: Set<string>): boolean {
  if (isJsUserInput(node)) return true;
  if (node.type === "Identifier" && tainted.has(node.name)) return true;
  if (node.type === "BinaryExpression") {
    return containsJsUserInputOrTainted(node.left, tainted) ||
           containsJsUserInputOrTainted(node.right, tainted);
  }
  return false;
}

/**
 * Collect JS/TS variables assigned from user input sources.
 * Handles: const x = req.body.name / const { file } = req.query
 */
export function collectJsTaintedVars(
  ast: unknown,
  walkFn: (ast: unknown, visitor: (node: TSESTree.Node) => void) => void,
): Set<string> {
  const tainted = new Set<string>();
  walkFn(ast, (node: TSESTree.Node) => {
    if (node.type !== "VariableDeclarator" || !node.init) return;

    if (isJsUserInput(node.init)) {
      if (node.id.type === "Identifier") tainted.add(node.id.name);
      if (node.id.type === "ObjectPattern") {
        for (const prop of node.id.properties) {
          if (prop.type === "Property" && prop.value.type === "Identifier") {
            tainted.add(prop.value.name);
          }
        }
      }
    }
    // Destructuring: const { url } = req.query
    if (
      node.id.type === "ObjectPattern" &&
      node.init.type === "MemberExpression" &&
      isJsUserInput(node.init)
    ) {
      for (const prop of node.id.properties) {
        if (prop.type === "Property" && prop.value.type === "Identifier") {
          tainted.add(prop.value.name);
        }
      }
    }
  });
  return tainted;
}

// ── Python User Input Sources ──

/** Python user input regex — covers request.*, input(), sys.argv */
export const PY_USER_INPUT = /\b(?:request\.\w+|input\s*\(|sys\.argv)/;

/** Python user input regex — web-only (no sys.argv), for XSS detection */
export const PY_USER_INPUT_WEB = /\b(?:request\.\w+|input\s*\()/;

/**
 * Collect Python tainted variables from tree-sitter AST.
 * Pass 1: direct user input assignments
 * Pass 2: transitive taint propagation
 */
export function collectPyTaintedVars(
  rootNode: TreeSitterNode,
  walkFn: (node: TreeSitterNode, visitor: (n: TreeSitterNode) => void) => void,
  userInputRegex: RegExp = PY_USER_INPUT,
): Set<string> {
  const tainted = new Set<string>();

  // Pass 1: direct user input sources
  walkFn(rootNode, (node: TreeSitterNode) => {
    if (node.type !== "assignment") return;
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (!left || !right || left.type !== "identifier") return;
    if (userInputRegex.test(right.text)) tainted.add(left.text);
  });

  // Pass 2: transitive — variables derived from tainted vars
  walkFn(rootNode, (node: TreeSitterNode) => {
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

  return tainted;
}

/**
 * Collect Python tainted variables from source lines (regex fallback).
 */
export function collectPyTaintedVarsRegex(
  lines: string[],
  userInputRegex: RegExp = PY_USER_INPUT,
): Set<string> {
  const tainted = new Set<string>();

  for (const l of lines) {
    const m = l.match(/^\s*(\w+)\s*=\s*/);
    if (!m) continue;
    const rhs = l.slice(l.indexOf("=") + 1);
    if (userInputRegex.test(rhs)) tainted.add(m[1]);
  }

  // Transitive
  for (const l of lines) {
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

  return tainted;
}

/**
 * Check if a tree-sitter node contains user input or tainted references.
 */
export function hasPyTaintedRef(
  node: TreeSitterNode,
  tainted: Set<string>,
  userInputRegex: RegExp = PY_USER_INPUT,
): boolean {
  if (node.type === "identifier" && tainted.has(node.text)) return true;
  if (userInputRegex.test(node.text)) return true;
  return node.namedChildren.some((c: TreeSitterNode) => hasPyTaintedRef(c, tainted, userInputRegex));
}
