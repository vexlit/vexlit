import type { Dependency, DepGraph } from "./types.js";

/**
 * Analyze which dependencies are reachable from actual imports in source code.
 *
 * Strategy:
 * 1. Extract all import/require package names from source files
 * 2. Map those to direct dependencies in the dep graph
 * 3. BFS through the graph to find all transitively reachable deps
 *
 * Returns a Set of reachable dep keys ("ecosystem:name@version")
 */
export function analyzeReachability(
  files: { path: string; content: string }[],
  depGraph: DepGraph,
  dependencies: Dependency[]
): Set<string> {
  // Step 1: Extract imported package names from source files
  const importedPackages = extractImportedPackages(files);

  // Step 2: Find dep-graph keys for directly imported packages
  const depKeysByName = new Map<string, string[]>();
  for (const dep of dependencies) {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    const existing = depKeysByName.get(dep.name) ?? [];
    existing.push(key);
    depKeysByName.set(dep.name, existing);
  }

  const reachable = new Set<string>();
  const queue: string[] = [];

  for (const pkgName of importedPackages) {
    const keys = depKeysByName.get(pkgName);
    if (!keys) continue;
    for (const key of keys) {
      if (!reachable.has(key)) {
        reachable.add(key);
        queue.push(key);
      }
    }
  }

  // Step 3: BFS through dep graph to find transitively reachable deps
  while (queue.length > 0) {
    const current = queue.shift()!;
    const children = depGraph.edges[current];
    if (!children) continue;
    for (const child of children) {
      if (!reachable.has(child)) {
        reachable.add(child);
        queue.push(child);
      }
    }
  }

  return reachable;
}

// ── Import extraction ──

const JS_IMPORT_RE = /(?:import\s+(?:[\s\S]*?\s+from\s+)?|import\s*\()['"]([^'"]+)['"]/g;
const JS_REQUIRE_RE = /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
const PY_IMPORT_RE = /^(?:import\s+(\S+)|from\s+(\S+)\s+import)/gm;

function extractImportedPackages(
  files: { path: string; content: string }[]
): Set<string> {
  const packages = new Set<string>();

  for (const file of files) {
    const ext = file.path.split(".").pop()?.toLowerCase() ?? "";

    if (["js", "jsx", "mjs", "cjs", "ts", "tsx"].includes(ext)) {
      extractJsImports(file.content, packages);
    } else if (ext === "py") {
      extractPyImports(file.content, packages);
    }
  }

  return packages;
}

function extractJsImports(content: string, out: Set<string>): void {
  for (const re of [JS_IMPORT_RE, JS_REQUIRE_RE]) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)) !== null) {
      const specifier = m[1];
      // Skip relative imports
      if (specifier.startsWith(".") || specifier.startsWith("/")) continue;
      // Extract package name (handle scoped packages)
      out.add(getPackageName(specifier));
    }
  }
}

function extractPyImports(content: string, out: Set<string>): void {
  PY_IMPORT_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = PY_IMPORT_RE.exec(content)) !== null) {
    const mod = m[1] ?? m[2];
    // Top-level module name (e.g., "flask" from "flask.request")
    const topLevel = mod.split(".")[0];
    out.add(topLevel);
  }
}

function getPackageName(specifier: string): string {
  // Scoped packages: @scope/package/subpath → @scope/package
  if (specifier.startsWith("@")) {
    const parts = specifier.split("/");
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : specifier;
  }
  // Regular packages: package/subpath → package
  return specifier.split("/")[0];
}
