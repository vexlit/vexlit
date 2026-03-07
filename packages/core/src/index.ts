export { scan, scanFile } from "./scanner.js";
export { RuleEngine } from "./rule-engine.js";
export { allRules } from "./rules/index.js";
export { allSecretPatterns, secretPatternRules } from "./secrets/index.js";
export { loadConfig } from "./config.js";
export { loadIgnorePatterns, isIgnored } from "./ignore.js";
export { analyzeLlm } from "./llm.js";
export { parseAST, walkAST, findNodes } from "./ast-parser.js";
export { parseTreeSitter, walkTreeSitter, findTreeSitterNodes } from "./tree-sitter.js";
export type { TreeSitterTree, TreeSitterNode } from "./tree-sitter.js";
export { scaDependencies, isDependencyFile, parseDependencies, generateCycloneDxSbom, analyzeLicenses, classifyLicense } from "./sca/index.js";
export type { Dependency, Advisory, ScaDependencyResult, ScaResult, LicenseRisk } from "./sca/index.js";
export type {
  Vulnerability,
  ScanResult,
  ScanOptions,
  ScanContext,
  VexlitConfig,
  RuleConfig,
  Severity,
  Confidence,
  Language,
  Rule,
} from "./types.js";
