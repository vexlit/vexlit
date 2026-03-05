import * as fs from "node:fs";
import * as path from "node:path";
import { Language, ScanOptions, ScanResult, VexlitConfig } from "./types.js";
import { RuleEngine } from "./rule-engine.js";
import { loadIgnorePatterns, isIgnored } from "./ignore.js";
import { loadConfig } from "./config.js";

const EXTENSION_MAP: Record<string, Language> = {
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".py": "python",
};

function detectLanguage(filePath: string): Language | null {
  const ext = path.extname(filePath).toLowerCase();
  return EXTENSION_MAP[ext] ?? null;
}

function collectFiles(
  dir: string,
  languages: Language[],
  ignorePatterns: string[]
): string[] {
  const results: string[] = [];
  const allowedExts = new Set(
    Object.entries(EXTENSION_MAP)
      .filter(([, lang]) => languages.includes(lang))
      .map(([ext]) => ext)
  );

  function walk(currentDir: string) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (isIgnored(fullPath, ignorePatterns)) continue;

      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (allowedExts.has(path.extname(entry.name).toLowerCase())) {
        results.push(fullPath);
      }
    }
  }

  walk(dir);
  return results;
}

const engine = new RuleEngine();

export function scanFile(
  filePath: string,
  config?: VexlitConfig
): ScanResult | null {
  const language = detectLanguage(filePath);
  if (!language) return null;

  const content = fs.readFileSync(filePath, "utf-8");
  const vulnerabilities = engine.execute(filePath, content, language, config);

  return {
    filePath,
    language,
    vulnerabilities,
    scannedAt: new Date().toISOString(),
  };
}

export function scan(options: ScanOptions): ScanResult[] {
  const rootDir = path.resolve(options.paths[0]);
  const resolvedRoot = fs.statSync(rootDir).isDirectory()
    ? rootDir
    : path.dirname(rootDir);
  const config = options.config ?? loadConfig(resolvedRoot);
  const languages = config.languages ?? ["javascript", "typescript", "python"];
  const ignorePatterns = loadIgnorePatterns(resolvedRoot);
  if (config.ignore) {
    ignorePatterns.push(...config.ignore);
  }

  const results: ScanResult[] = [];

  for (const targetPath of options.paths) {
    const stat = fs.statSync(targetPath);

    if (stat.isFile()) {
      if (!isIgnored(targetPath, ignorePatterns)) {
        const result = scanFile(targetPath, config);
        if (result) results.push(result);
      }
    } else if (stat.isDirectory()) {
      const files = collectFiles(targetPath, languages, ignorePatterns);
      for (const file of files) {
        const result = scanFile(file, config);
        if (result) results.push(result);
      }
    }
  }

  return results;
}
