import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const SECRET_PATTERNS: { name: string; pattern: RegExp }[] = [
  {
    name: "AWS Access Key",
    pattern: /(?:AKIA[0-9A-Z]{16})/,
  },
  {
    name: "Generic API Key assignment",
    pattern:
      /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["'`][A-Za-z0-9+/=_\-]{16,}["'`]/i,
  },
  {
    name: "Hardcoded password",
    pattern:
      /(?:password|passwd|pwd)\s*[:=]\s*["'`][^"'`]{4,}["'`]/i,
  },
  {
    name: "Private key",
    pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/,
  },
  {
    name: "GitHub token",
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/,
  },
];

const SAFE_ENV_PATTERNS = /process\.env|os\.environ|import\.meta\.env|System\.getenv/;
const SECRET_VAR_NAMES = /(?:password|passwd|pwd|secret|api[_-]?key|token|auth)/i;

function isEnvAssignmentAST(ast: AST, line: number): boolean {
  let isSafe = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (
      node.type === "VariableDeclarator" &&
      node.loc &&
      node.loc.start.line === line &&
      node.init
    ) {
      // const password = process.env.PASSWORD
      if (
        node.init.type === "MemberExpression" &&
        node.init.object.type === "MemberExpression"
      ) {
        const src = getMemberSource(node.init.object);
        if (src === "process.env" || src === "import.meta.env") {
          isSafe = true;
        }
      }
      // const password = env.PASSWORD or config.password
      if (
        node.init.type === "MemberExpression" &&
        node.init.object.type === "Identifier"
      ) {
        const objName = node.init.object.name.toLowerCase();
        if (objName === "env" || objName === "config" || objName === "settings") {
          isSafe = true;
        }
      }
      // const password = getEnv("PASSWORD")
      if (
        node.init.type === "CallExpression" &&
        node.init.callee.type === "Identifier"
      ) {
        const fnName = node.init.callee.name.toLowerCase();
        if (fnName.includes("env") || fnName.includes("config") || fnName.includes("secret")) {
          isSafe = true;
        }
      }
    }
    // Property: password: process.env.PASSWORD
    if (
      node.type === "Property" &&
      node.loc &&
      node.loc.start.line === line &&
      node.value.type === "MemberExpression"
    ) {
      const src = getMemberSource(node.value);
      if (src?.startsWith("process.env")) {
        isSafe = true;
      }
    }
  });
  return isSafe;
}

function getMemberSource(node: TSESTree.MemberExpression): string {
  if (node.object.type === "Identifier" && node.property.type === "Identifier") {
    return `${node.object.name}.${node.property.name}`;
  }
  if (node.object.type === "MemberExpression" && node.property.type === "Identifier") {
    return `${getMemberSource(node.object)}.${node.property.name}`;
  }
  return "";
}

export const hardcodedSecretsRule: Rule = {
  id: "VEXLIT-001",
  name: "Hardcoded Secret",
  severity: "critical",
  description: "Hardcoded secrets or API keys detected in source code",
  cwe: "CWE-798",
  owasp: "A02:2021",
  languages: ["javascript", "typescript", "python"],
  suggestion: "Move secrets to environment variables or a secrets manager",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];

      for (const { name, pattern } of SECRET_PATTERNS) {
        if (!pattern.test(line)) continue;

        // Regex found a match — now AST-verify if possible
        const lineNum = i + 1;

        // Quick regex check: skip if right-hand side references env
        if (SAFE_ENV_PATTERNS.test(line)) continue;

        // AST verification for JS/TS: check if the value is from env/config
        if (ast && (ctx.language === "javascript" || ctx.language === "typescript")) {
          if (isEnvAssignmentAST(ast, lineNum)) continue;
        }

        vulnerabilities.push({
          ruleId: this.id,
          ruleName: this.name,
          severity: this.severity,
          message: `${name} found in source code`,
          filePath: ctx.filePath,
          line: lineNum,
          column: line.search(pattern) + 1,
          snippet: line.trim(),
          cwe: this.cwe,
          owasp: this.owasp,
          suggestion: this.suggestion,
        });
      }
    }

    return vulnerabilities;
  },
};
