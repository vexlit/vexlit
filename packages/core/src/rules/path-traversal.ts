import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const PATH_TRAVERSAL_REGEX =
  /(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream|open|access|stat|unlink|rmdir|mkdir)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|`)/;

const PATH_JOIN_REGEX =
  /path\.(?:join|resolve)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/;

const FS_METHODS = new Set([
  "readFile", "readFileSync", "writeFile", "writeFileSync",
  "createReadStream", "createWriteStream", "open", "openSync",
  "access", "accessSync", "stat", "statSync",
  "unlink", "unlinkSync", "rmdir", "rmdirSync", "mkdir", "mkdirSync",
]);

function hasPathTraversalAST(ast: AST, line: number): boolean {
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
      if (!calleeName) return;

      // fs.readFile(req.query.file) etc.
      if (FS_METHODS.has(calleeName)) {
        const firstArg = node.arguments[0];
        if (isUserInputExpression(firstArg) || isUnsafeTemplate(firstArg)) {
          found = true;
          return;
        }
      }

      // path.join(base, req.params.file)
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

function isUnsafeTemplate(node: TSESTree.Node): boolean {
  return node.type === "TemplateLiteral" && node.expressions.length > 0;
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

export const pathTraversalRule: Rule = {
  id: "VEXLIT-021",
  name: "Path Traversal",
  severity: "critical",
  description: "Unsanitized user input used in file system operations allows directory traversal",
  cwe: "CWE-22",
  owasp: "A01:2021",
  languages: ["javascript", "typescript", "python"],
  suggestion: "Validate and sanitize file paths. Use path.resolve() with a base directory and verify the result stays within allowed boundaries. Never pass user input directly to fs operations.",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];
      if (!PATH_TRAVERSAL_REGEX.test(line) && !PATH_JOIN_REGEX.test(line)) continue;

      const lineNum = i + 1;

      if (ast && (ctx.language === "javascript" || ctx.language === "typescript")) {
        if (!hasPathTraversalAST(ast, lineNum)) continue;
      }

      vulnerabilities.push({
        ruleId: this.id, ruleName: this.name, severity: this.severity,
        message: "Path traversal — unsanitized user input in file system operation",
        filePath: ctx.filePath, line: lineNum, column: 1,
        snippet: line.trim(),
        cwe: this.cwe, owasp: this.owasp, suggestion: this.suggestion,
      });
    }
    return vulnerabilities;
  },
};
