import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const CMD_INJECTION_REGEX =
  /(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|`)/;

const PYTHON_CMD_REGEX =
  /(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output|check_call))\s*\(\s*(?:f["']|request\.|input)/;

const SHELL_EXEC_METHODS = new Set([
  "exec", "execSync", "execFile", "execFileSync",
  "spawn", "spawnSync", "fork",
]);

function hasCommandInjectionAST(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;
    if (
      node.type === "CallExpression" &&
      node.loc &&
      node.loc.start.line === line &&
      node.arguments.length > 0
    ) {
      const calleeName = getCalleeName(node.callee);
      if (!calleeName || !SHELL_EXEC_METHODS.has(calleeName)) return;

      const firstArg = node.arguments[0];

      // exec(`rm ${req.query.file}`)
      if (firstArg.type === "TemplateLiteral" && firstArg.expressions.length > 0) {
        found = true;
        return;
      }

      // exec(req.body.cmd)
      if (isUserInputExpression(firstArg)) {
        found = true;
        return;
      }

      // exec("cmd " + userInput)
      if (firstArg.type === "BinaryExpression" && firstArg.operator === "+") {
        if (containsUserInput(firstArg)) {
          found = true;
          return;
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

function containsUserInput(node: TSESTree.Node): boolean {
  if (isUserInputExpression(node)) return true;
  if (node.type === "BinaryExpression") {
    return containsUserInput(node.left) || containsUserInput(node.right);
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

export const commandInjectionRule: Rule = {
  id: "VEXLIT-022",
  name: "Command Injection",
  severity: "critical",
  description: "Unsanitized user input passed to shell execution functions",
  cwe: "CWE-78",
  owasp: "A03:2021",
  languages: ["javascript", "typescript", "python"],
  suggestion: "Never pass user input to shell commands. Use execFile/spawn with argument arrays instead of exec. Validate and sanitize all inputs against an allowlist.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];
      if (!CMD_INJECTION_REGEX.test(line) && !PYTHON_CMD_REGEX.test(line)) continue;

      const lineNum = i + 1;

      if (ast && (ctx.language === "javascript" || ctx.language === "typescript")) {
        if (!hasCommandInjectionAST(ast, lineNum)) continue;
      }

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "Command injection — unsanitized user input in shell command",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: line.trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
          confidence: "high",
      });
    }
    return vulnerabilities;
  },
};
