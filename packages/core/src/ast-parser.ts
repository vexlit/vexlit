import { parse } from "@typescript-eslint/typescript-estree";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { Language } from "./types.js";

export type ASTNode = TSESTree.Node;
export type AST = TSESTree.Program;

export function parseAST(
  content: string,
  language: Language
): AST | null {
  if (language === "javascript" || language === "typescript") {
    try {
      return parse(content, {
        jsx: true,
        loc: true,
        range: true,
        comment: false,
        errorOnUnknownASTType: false,
      });
    } catch {
      return null;
    }
  }

  // Python: not yet supported, return null
  return null;
}

export function walkAST(
  node: TSESTree.Node,
  visitor: (node: TSESTree.Node) => void
): void {
  visitor(node);
  for (const key of Object.keys(node)) {
    const child = (node as unknown as Record<string, unknown>)[key];
    if (child && typeof child === "object") {
      if (Array.isArray(child)) {
        for (const item of child) {
          if (item && typeof item === "object" && "type" in item) {
            walkAST(item as TSESTree.Node, visitor);
          }
        }
      } else if ("type" in child) {
        walkAST(child as TSESTree.Node, visitor);
      }
    }
  }
}

export function findNodes(
  ast: AST,
  nodeType: string
): TSESTree.Node[] {
  const results: TSESTree.Node[] = [];
  walkAST(ast, (node) => {
    if (node.type === nodeType) {
      results.push(node);
    }
  });
  return results;
}
