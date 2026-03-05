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
      const content = fs.readFileSync(filePath, "utf-8");
      // Support: export default { ... }
      const exportDefaultMatch = content.match(/export\s+default\s+(\{[\s\S]*\})/);
      if (exportDefaultMatch) {
        const fn = new Function(`return ${exportDefaultMatch[1]}`);
        return fn() as VexlitConfig;
      }
      // Support: module.exports = { ... }
      const cjsMatch = content.match(/module\.exports\s*=\s*(\{[\s\S]*\})/);
      if (cjsMatch) {
        const fn = new Function(`return ${cjsMatch[1]}`);
        return fn() as VexlitConfig;
      }
    }
  }

  return {};
}
