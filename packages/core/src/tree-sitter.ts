import { Language } from "./types.js";
import * as path from "node:path";

// web-tree-sitter types
interface TreeSitterParser {
  parse(input: string): TreeSitterTree;
  setLanguage(lang: TreeSitterLanguage): void;
}

export interface TreeSitterTree {
  rootNode: TreeSitterNode;
}

export interface TreeSitterNode {
  type: string;
  text: string;
  startPosition: { row: number; column: number };
  endPosition: { row: number; column: number };
  childCount: number;
  children: TreeSitterNode[];
  namedChildren: TreeSitterNode[];
  parent: TreeSitterNode | null;
  childForFieldName(name: string): TreeSitterNode | null;
}

interface TreeSitterLanguage {}

// web-tree-sitter v0.24 CJS export:
// module.exports = TreeSitter (constructor function)
// TreeSitter.init() → initializes WASM
// TreeSitter.Language.load() → loads grammar
// new TreeSitter() → parser instance
interface TreeSitterConstructor {
  init(options?: { locateFile?: (file: string, prefix: string) => string }): Promise<void>;
  Language: {
    load(path: string): Promise<TreeSitterLanguage>;
  };
  new (): TreeSitterParser;
}

let TreeSitter: TreeSitterConstructor | null = null;
let initialized = false;
let initFailed = false;
const languageCache = new Map<string, TreeSitterLanguage>();

// Dynamic require to prevent webpack from bundling WASM
function dynamicRequire(mod: string): unknown {
  // eslint-disable-next-line @typescript-eslint/no-require-imports, no-eval
  return eval("require")(mod);
}

function dynamicResolve(mod: string): string {
  // eslint-disable-next-line no-eval
  return eval("require.resolve")(mod) as string;
}

async function ensureInit(): Promise<TreeSitterConstructor | null> {
  if (initialized && TreeSitter) return TreeSitter;
  if (initFailed) return null;

  try {
    const TS = dynamicRequire("web-tree-sitter") as TreeSitterConstructor;
    const tsModulePath = dynamicResolve("web-tree-sitter");
    const tsDir = path.dirname(tsModulePath);

    await TS.init({
      locateFile: (file: string) => path.join(tsDir, file),
    });

    TreeSitter = TS;
    initialized = true;
    return TreeSitter;
  } catch {
    initFailed = true;
    return null;
  }
}

function resolveGrammarPath(grammarName: string): string {
  return dynamicResolve(
    path.join("tree-sitter-wasms", "out", `tree-sitter-${grammarName}.wasm`)
  );
}

const LANG_GRAMMAR: Record<Language, string> = {
  javascript: "javascript",
  typescript: "typescript",
  python: "python",
};

async function getLanguage(lang: Language): Promise<TreeSitterLanguage | null> {
  const cached = languageCache.get(lang);
  if (cached) return cached;

  const TS = await ensureInit();
  if (!TS) return null;

  const grammarName = LANG_GRAMMAR[lang];
  const grammarPath = resolveGrammarPath(grammarName);
  const language = await TS.Language.load(grammarPath);
  languageCache.set(lang, language);
  return language;
}

export async function parseTreeSitter(
  content: string,
  language: Language
): Promise<TreeSitterTree | null> {
  try {
    const TS = await ensureInit();
    if (!TS) return null;

    const parser = new TS();
    const lang = await getLanguage(language);
    if (!lang) return null;

    parser.setLanguage(lang);
    return parser.parse(content);
  } catch {
    return null;
  }
}

export function walkTreeSitter(
  node: TreeSitterNode,
  visitor: (node: TreeSitterNode) => void
): void {
  visitor(node);
  for (const child of node.children) {
    walkTreeSitter(child, visitor);
  }
}

export function findTreeSitterNodes(
  tree: TreeSitterTree,
  nodeType: string
): TreeSitterNode[] {
  const results: TreeSitterNode[] = [];
  walkTreeSitter(tree.rootNode, (node) => {
    if (node.type === nodeType) {
      results.push(node);
    }
  });
  return results;
}
