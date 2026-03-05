import { Rule, Vulnerability, Language, VexlitConfig, ScanContext } from "./types.js";
import { allRules } from "./rules/index.js";
import { parseAST } from "./ast-parser.js";

export class RuleEngine {
  private registry: Map<string, Rule> = new Map();

  constructor() {
    for (const rule of allRules) {
      this.register(rule);
    }
  }

  register(rule: Rule): void {
    this.registry.set(rule.id, rule);
  }

  getRules(): Rule[] {
    return Array.from(this.registry.values());
  }

  getRule(id: string): Rule | undefined {
    return this.registry.get(id);
  }

  createContext(
    filePath: string,
    content: string,
    language: Language
  ): ScanContext {
    return {
      filePath,
      content,
      lines: content.split("\n"),
      language,
      ast: parseAST(content, language),
    };
  }

  execute(
    filePath: string,
    content: string,
    language: Language,
    config?: VexlitConfig
  ): Vulnerability[] {
    const ctx = this.createContext(filePath, content, language);
    const vulnerabilities: Vulnerability[] = [];

    for (const rule of this.registry.values()) {
      if (!rule.languages.includes(language)) continue;

      const ruleConfig = config?.rules?.[rule.id];
      if (ruleConfig === false) continue;
      if (ruleConfig && ruleConfig.enabled === false) continue;

      const results = rule.scan(ctx);

      if (ruleConfig && ruleConfig.severity) {
        for (const v of results) {
          v.severity = ruleConfig.severity;
        }
      }

      vulnerabilities.push(...results);
    }

    return vulnerabilities;
  }
}
