import * as fs from "node:fs";
import * as path from "node:path";
import { VexlitConfig } from "./types.js";

const CONFIG_FILES = [
  "vexlit.config.js",
  "vexlit.config.json",
  ".vexlitrc.json",
];

export function loadConfig(rootDir: string): VexlitConfig {
  for (const fileName of CONFIG_FILES) {
    const filePath = path.join(rootDir, fileName);
    if (!fs.existsSync(filePath)) continue;

    if (fileName.endsWith(".json")) {
      const content = fs.readFileSync(filePath, "utf-8");
      return JSON.parse(content) as VexlitConfig;
    }

    if (fileName.endsWith(".js")) {
      // For .js config, read and parse as JSON-like module.exports
      const content = fs.readFileSync(filePath, "utf-8");
      const match = content.match(/module\.exports\s*=\s*(\{[\s\S]*\})/);
      if (match) {
        const fn = new Function(`return ${match[1]}`);
        return fn() as VexlitConfig;
      }
    }
  }

  return {};
}
