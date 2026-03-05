import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const UNSAFE_FILE_PATTERNS: { name: string; pattern: RegExp }[] = [
  {
    name: "Path traversal via user input",
    pattern:
      /(?:readFile|writeFile|createReadStream|createWriteStream|open)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/,
  },
  {
    name: "Unsanitized path join with user input",
    pattern:
      /path\.(?:join|resolve)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/,
  },
  {
    name: "Python open with user input",
    pattern: /open\s*\(\s*(?:request\.|f["']|input)/,
  },
  {
    name: "Command injection via exec/spawn",
    pattern:
      /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|`)/,
  },
  {
    name: "Python os.system / subprocess with user input",
    pattern:
      /(?:os\.system|subprocess\.(?:call|run|Popen))\s*\(\s*(?:f["']|request\.|input)/,
  },
];

const DANGEROUS_CALLEES = new Set([
  "exec", "execSync", "spawn", "spawnSync",
  "readFile", "readFileSync", "writeFile", "writeFileSync",
  "createReadStream", "createWriteStream",
]);

function hasUnsafeCallAtLine(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;

    if (
      node.type === "CallExpression" &&
      node.loc &&
      node.loc.start.line === line
    ) {
      const calleeName = getCalleeName(node.callee);
      if (!calleeName) return;

      // Check: exec/spawn/readFile/etc with template literal arg
      if (DANGEROUS_CALLEES.has(calleeName) && node.arguments.length > 0) {
        const firstArg = node.arguments[0];
        // Template literal with expressions = injection risk
        if (firstArg.type === "TemplateLiteral" && firstArg.expressions.length > 0) {
          found = true;
          return;
        }
        // MemberExpression from req/request = user input
        if (isUserInputExpression(firstArg)) {
          found = true;
          return;
        }
      }

      // path.join(something, req.params.file)
      if (
        (calleeName === "join" || calleeName === "resolve") &&
        node.callee.type === "MemberExpression" &&
        node.callee.object.type === "Identifier" &&
        node.callee.object.name === "path"
      ) {
        for (const arg of node.arguments) {
          if (isUserInputExpression(arg)) {
            found = true;
            return;
          }
        }
      }
    }
  });
  return found;
}

function getCalleeName(callee: TSESTree.Node): string | null {
  if (callee.type === "Identifier") return callee.name;
  if (
    callee.type === "MemberExpression" &&
    callee.property.type === "Identifier"
  ) {
    return callee.property.name;
  }
  return null;
}

function isUserInputExpression(node: TSESTree.Node): boolean {
  if (node.type === "MemberExpression") {
    const src = flattenMember(node);
    return /^(req|request)\.(params|query|body|headers)/.test(src);
  }
  return false;
}

function flattenMember(node: TSESTree.MemberExpression): string {
  const prop =
    node.property.type === "Identifier" ? node.property.name : "?";
  if (node.object.type === "Identifier") {
    return `${node.object.name}.${prop}`;
  }
  if (node.object.type === "MemberExpression") {
    return `${flattenMember(node.object)}.${prop}`;
  }
  return prop;
}

/** @deprecated Use VEXLIT-021 (Path Traversal) + VEXLIT-022 (Command Injection) instead */
export const unsafeFileAccessRule: Rule = {
  id: "VEXLIT-005",
  name: "Unsafe File Access / Command Injection (deprecated)",
  severity: "critical",
  description: "Unsanitized user input used in file operations or shell commands",
  cwe: "CWE-78",
  owasp: "A03:2021",
  languages: ["javascript", "typescript", "python"],
  suggestion: "Validate and sanitize all file paths. Use allowlists for permitted directories. Never pass user input directly to shell commands.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];

      for (const { name, pattern } of UNSAFE_FILE_PATTERNS) {
        if (!pattern.test(line)) continue;

        const lineNum = i + 1;

        // AST verification for JS/TS
        if (ast && (ctx.language === "javascript" || ctx.language === "typescript")) {
          if (!hasUnsafeCallAtLine(ast, lineNum)) continue;
        }

        vulnerabilities.push({
          ruleId: this.id,
          ruleName: this.name,
          severity: this.severity,
          message: `${name} — potential path traversal or command injection`,
          filePath: ctx.filePath,
          line: lineNum,
          column: 1,
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
