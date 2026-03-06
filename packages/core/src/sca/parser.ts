import type { Dependency } from "./types.js";

/** Files that contain dependency declarations */
export const DEPENDENCY_FILES = new Set([
  "package.json",
  "requirements.txt",
  "Pipfile",
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
  if (fileName === "requirements.txt") return parseRequirementsTxt(filePath, content);
  if (fileName === "Pipfile") return parsePipfile(filePath, content);

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
