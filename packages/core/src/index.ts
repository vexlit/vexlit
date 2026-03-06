export { scan, scanFile } from "./scanner.js";
export { RuleEngine } from "./rule-engine.js";
export { allRules } from "./rules/index.js";
export { allSecretPatterns, secretPatternRules } from "./secrets/index.js";
export { loadConfig } from "./config.js";
export { loadIgnorePatterns, isIgnored } from "./ignore.js";
export { analyzeLlm } from "./llm.js";
export { parseAST, walkAST, findNodes } from "./ast-parser.js";
export type {
  Vulnerability,
  ScanResult,
  ScanOptions,
  ScanContext,
  VexlitConfig,
  RuleConfig,
  Severity,
  Language,
  Rule,
} from "./types.js";
