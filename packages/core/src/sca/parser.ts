import type { Dependency } from "./types.js";

/** Files that contain dependency declarations */
export const DEPENDENCY_FILES = new Set([
  "package.json",
  "package-lock.json",
  "requirements.txt",
  "Pipfile",
  "go.mod",
  "go.sum",
  "Cargo.toml",
  "Cargo.lock",
]);

/** Check if a file path is a dependency manifest */
export function isDependencyFile(filePath: string): boolean {
  const name = filePath.split("/").pop() ?? "";
  return DEPENDENCY_FILES.has(name);
}

/** Parse dependencies from a file based on its name */
export function parseDependencies(
  filePath: string,
  content: string
): Dependency[] {
  const fileName = filePath.split("/").pop() ?? "";

  if (fileName === "package.json") return parsePackageJson(filePath, content);
  if (fileName === "package-lock.json") return parsePackageLockJson(filePath, content);
  if (fileName === "requirements.txt") return parseRequirementsTxt(filePath, content);
  if (fileName === "Pipfile") return parsePipfile(filePath, content);
  if (fileName === "go.mod") return parseGoMod(filePath, content);
  if (fileName === "go.sum") return parseGoSum(filePath, content);
  if (fileName === "Cargo.toml") return parseCargoToml(filePath, content);
  if (fileName === "Cargo.lock") return parseCargoLock(filePath, content);

  return [];
}

/** Parse package.json for npm dependencies */
function parsePackageJson(filePath: string, content: string): Dependency[] {
  const deps: Dependency[] = [];

  try {
    const pkg = JSON.parse(content);

    const addDeps = (
      depsObj: Record<string, string> | undefined,
      dev: boolean,
      startLine: number
    ) => {
      if (!depsObj) return;
      const keys = Object.keys(depsObj);

      for (let i = 0; i < keys.length; i++) {
        const name = keys[i];
        const raw = depsObj[name];
        const version = cleanVersion(raw);
        if (!version) continue;

        // Estimate line number by searching content
        const line = findJsonKeyLine(content, name, startLine);

        deps.push({
          name,
          version,
          ecosystem: "npm",
          source: filePath,
          line,
          dev,
        });
      }
    };

    const depsSectionLine = findJsonKeyLine(content, "dependencies", 1);
    const devDepsSectionLine = findJsonKeyLine(content, "devDependencies", 1);

    addDeps(pkg.dependencies, false, depsSectionLine);
    addDeps(pkg.devDependencies, true, devDepsSectionLine);
  } catch {
    // Invalid JSON — skip
  }

  return deps;
}

/** Parse requirements.txt for Python dependencies */
function parseRequirementsTxt(
  filePath: string,
  content: string
): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Skip empty, comments, options
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;

    // Match: package==version or package>=version
    const match = line.match(
      /^([a-zA-Z0-9_][a-zA-Z0-9._-]*)(?:\[.*?\])?\s*==\s*([^\s;#,]+)/
    );
    if (match) {
      deps.push({
        name: match[1].toLowerCase(),
        version: match[2],
        ecosystem: "PyPI",
        source: filePath,
        line: i + 1,
        dev: false,
      });
    }
  }

  return deps;
}

/** Parse Pipfile [packages] and [dev-packages] sections */
function parsePipfile(filePath: string, content: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");

  let currentSection: "packages" | "dev-packages" | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Section headers
    if (line === "[packages]") {
      currentSection = "packages";
      continue;
    }
    if (line === "[dev-packages]") {
      currentSection = "dev-packages";
      continue;
    }
    if (line.startsWith("[")) {
      currentSection = null;
      continue;
    }

    if (!currentSection) continue;
    if (!line || line.startsWith("#")) continue;

    // Match: package = "==version" or package = ">=version"
    const match = line.match(
      /^([a-zA-Z0-9_][a-zA-Z0-9._-]*)\s*=\s*"==([^"]+)"/
    );
    if (match) {
      deps.push({
        name: match[1].toLowerCase(),
        version: match[2],
        ecosystem: "PyPI",
        source: filePath,
        line: i + 1,
        dev: currentSection === "dev-packages",
      });
    }
  }

  return deps;
}

/** Parse go.mod for Go module dependencies */
function parseGoMod(filePath: string, content: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");

  let inRequireBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Single-line require: require github.com/pkg/errors v0.9.1
    if (line.startsWith("require ") && !line.includes("(")) {
      const match = line.match(/^require\s+(\S+)\s+(v\S+)/);
      if (match) {
        deps.push({
          name: match[1],
          version: match[2],
          ecosystem: "Go",
          source: filePath,
          line: i + 1,
          dev: false,
        });
      }
      continue;
    }

    // Block require
    if (line === "require (") {
      inRequireBlock = true;
      continue;
    }
    if (line === ")" && inRequireBlock) {
      inRequireBlock = false;
      continue;
    }

    if (inRequireBlock) {
      // Match: github.com/pkg/errors v0.9.1
      const match = line.match(/^(\S+)\s+(v\S+)/);
      if (match && !line.startsWith("//")) {
        deps.push({
          name: match[1],
          version: match[2],
          ecosystem: "Go",
          source: filePath,
          line: i + 1,
          dev: false,
        });
      }
    }
  }

  return deps;
}

/** Parse Cargo.toml for Rust crate dependencies */
function parseCargoToml(filePath: string, content: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");

  let currentSection: "dependencies" | "dev-dependencies" | "build-dependencies" | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Section headers
    if (line === "[dependencies]") {
      currentSection = "dependencies";
      continue;
    }
    if (line === "[dev-dependencies]") {
      currentSection = "dev-dependencies";
      continue;
    }
    if (line === "[build-dependencies]") {
      currentSection = "build-dependencies";
      continue;
    }
    if (line.startsWith("[")) {
      currentSection = null;
      continue;
    }

    if (!currentSection) continue;
    if (!line || line.startsWith("#")) continue;

    // Simple format: serde = "1.0"
    const simpleMatch = line.match(
      /^([a-zA-Z0-9_][a-zA-Z0-9_-]*)\s*=\s*"([^"]+)"/
    );
    if (simpleMatch) {
      const version = cleanVersion(simpleMatch[2]);
      if (version) {
        deps.push({
          name: simpleMatch[1],
          version,
          ecosystem: "crates.io",
          source: filePath,
          line: i + 1,
          dev: currentSection !== "dependencies",
        });
      }
      continue;
    }

    // Table format: serde = { version = "1.0", features = [...] }
    const tableMatch = line.match(
      /^([a-zA-Z0-9_][a-zA-Z0-9_-]*)\s*=\s*\{.*?version\s*=\s*"([^"]+)"/
    );
    if (tableMatch) {
      const version = cleanVersion(tableMatch[2]);
      if (version) {
        deps.push({
          name: tableMatch[1],
          version,
          ecosystem: "crates.io",
          source: filePath,
          line: i + 1,
          dev: currentSection !== "dependencies",
        });
      }
    }
  }

  return deps;
}

/** Parse package-lock.json for exact resolved versions (including transitive) */
function parsePackageLockJson(filePath: string, content: string): Dependency[] {
  const deps: Dependency[] = [];

  try {
    const lock = JSON.parse(content);

    // lockfileVersion 2/3: "packages" field
    if (lock.packages && typeof lock.packages === "object") {
      for (const [pkgPath, info] of Object.entries(lock.packages)) {
        if (!pkgPath) continue; // skip root entry ""
        const meta = info as { version?: string; dev?: boolean };
        if (!meta.version) continue;
        // Extract name from "node_modules/@scope/pkg" or "node_modules/pkg"
        const name = pkgPath.replace(/^.*node_modules\//, "");
        if (!name) continue;

        deps.push({
          name,
          version: meta.version,
          ecosystem: "npm",
          source: filePath,
          line: 1,
          dev: meta.dev ?? false,
        });
      }
    }
    // lockfileVersion 1 fallback: "dependencies" field
    else if (lock.dependencies && typeof lock.dependencies === "object") {
      const walk = (
        depsObj: Record<string, { version?: string; dev?: boolean; dependencies?: Record<string, unknown> }>,
      ) => {
        for (const [name, info] of Object.entries(depsObj)) {
          if (!info.version) continue;
          deps.push({
            name,
            version: info.version,
            ecosystem: "npm",
            source: filePath,
            line: 1,
            dev: info.dev ?? false,
          });
          // Nested dependencies (hoisting)
          if (info.dependencies) {
            walk(info.dependencies as typeof depsObj);
          }
        }
      };
      walk(lock.dependencies);
    }
  } catch {
    // Invalid JSON
  }

  return deps;
}

/** Parse go.sum for exact resolved versions (including transitive) */
function parseGoSum(filePath: string, content: string): Dependency[] {
  const deps: Dependency[] = [];
  const seen = new Set<string>();
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    // Skip /go.mod checksum lines — only keep module checksum lines
    if (line.includes("/go.mod ")) continue;

    // Format: module version h1:hash=
    const match = line.match(/^(\S+)\s+(v[^\s/]+)\s+h1:/);
    if (!match) continue;

    const name = match[1];
    const version = match[2];
    const key = `${name}@${version}`;

    if (seen.has(key)) continue;
    seen.add(key);

    deps.push({
      name,
      version,
      ecosystem: "Go",
      source: filePath,
      line: i + 1,
      dev: false,
    });
  }

  return deps;
}

/** Parse Cargo.lock for exact resolved versions (including transitive) */
function parseCargoLock(filePath: string, content: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");

  let currentName: string | null = null;
  let currentVersion: string | null = null;
  let blockLine = 0;

  const flush = () => {
    if (currentName && currentVersion) {
      deps.push({
        name: currentName,
        version: currentVersion,
        ecosystem: "crates.io",
        source: filePath,
        line: blockLine,
        dev: false,
      });
    }
    currentName = null;
    currentVersion = null;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    if (line === "[[package]]") {
      flush();
      blockLine = i + 1;
      continue;
    }

    const nameMatch = line.match(/^name\s*=\s*"([^"]+)"/);
    if (nameMatch) {
      currentName = nameMatch[1];
      continue;
    }

    const versionMatch = line.match(/^version\s*=\s*"([^"]+)"/);
    if (versionMatch) {
      currentVersion = versionMatch[1];
    }
  }
  flush();

  return deps;
}

/** Strip semver range characters to get a clean version */
function cleanVersion(raw: string): string | null {
  // Remove ^, ~, >=, <=, >, <, = prefixes
  const cleaned = raw.replace(/^[\^~>=<]+/, "").trim();
  // Must start with a digit and look like a version
  if (/^\d+\.\d+/.test(cleaned)) return cleaned;
  // Handles "latest", "*", "workspace:*", etc.
  return null;
}

/** Find the line number where a JSON key appears */
function findJsonKeyLine(
  content: string,
  key: string,
  startLine: number
): number {
  const lines = content.split("\n");
  const needle = `"${key}"`;
  for (let i = Math.max(0, startLine - 1); i < lines.length; i++) {
    if (lines[i].includes(needle)) return i + 1;
  }
  return startLine;
}
