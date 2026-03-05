import * as fs from "node:fs";
import * as path from "node:path";

const DEFAULT_IGNORE = [
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "__pycache__",
  ".venv",
  "venv",
  "coverage",
];

export function loadIgnorePatterns(rootDir: string): string[] {
  const patterns = [...DEFAULT_IGNORE];

  const ignoreFile = path.join(rootDir, ".vexlitignore");
  if (fs.existsSync(ignoreFile)) {
    const content = fs.readFileSync(ignoreFile, "utf-8");
    const lines = content
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("#"));
    patterns.push(...lines);
  }

  return patterns;
}

export function isIgnored(filePath: string, patterns: string[]): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  for (const pattern of patterns) {
    if (normalized.includes(`/${pattern}/`) || normalized.endsWith(`/${pattern}`)) {
      return true;
    }
    if (pattern.startsWith("*.")) {
      const ext = pattern.slice(1);
      if (normalized.endsWith(ext)) return true;
    }
  }
  return false;
}
