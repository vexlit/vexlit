import { Rule, Vulnerability, ScanContext } from "../types.js";
import type { TSESTree } from "@typescript-eslint/typescript-estree";
import { walkAST } from "../ast-parser.js";
import type { AST } from "../ast-parser.js";

const INSECURE_CRYPTO_PATTERNS: { name: string; pattern: RegExp }[] = [
  {
    name: "MD5 usage",
    pattern: /(?:createHash|hashlib\.md5|MD5)\s*\(\s*["']?md5["']?\s*\)/i,
  },
  {
    name: "SHA1 usage",
    pattern: /(?:createHash|hashlib\.sha1)\s*\(\s*["']?sha1["']?\s*\)/i,
  },
  {
    name: "Math.random for security",
    pattern: /Math\.random\s*\(\s*\)/,
  },
  {
    name: "Weak DES/RC4 cipher",
    pattern: /(?:createCipher(?:iv)?|DES|RC4)\s*\(\s*["'](?:des|rc4|des-ede)/i,
  },
];

function hasCreateHashAtLine(ast: AST, line: number, weakAlgo: string): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;

    // crypto.createHash("md5") or createHash("sha1")
    if (
      node.type === "CallExpression" &&
      node.loc &&
      node.loc.start.line === line &&
      node.arguments.length > 0 &&
      node.arguments[0].type === "Literal" &&
      typeof node.arguments[0].value === "string" &&
      node.arguments[0].value.toLowerCase() === weakAlgo
    ) {
      const callee = node.callee;
      if (
        (callee.type === "MemberExpression" &&
          callee.property.type === "Identifier" &&
          callee.property.name === "createHash") ||
        (callee.type === "Identifier" && callee.name === "createHash")
      ) {
        found = true;
      }
    }
  });
  return found;
}

function hasMathRandomAtLine(ast: AST, line: number): boolean {
  let found = false;
  walkAST(ast, (node: TSESTree.Node) => {
    if (found) return;

    if (
      node.type === "CallExpression" &&
      node.loc &&
      node.loc.start.line === line &&
      node.callee.type === "MemberExpression" &&
      node.callee.object.type === "Identifier" &&
      node.callee.object.name === "Math" &&
      node.callee.property.type === "Identifier" &&
      node.callee.property.name === "random"
    ) {
      found = true;
    }
  });
  return found;
}

export const insecureCryptoRule: Rule = {
  id: "VEXLIT-004",
  name: "Insecure Cryptography",
  severity: "warning",
  description: "Use of weak or broken cryptographic algorithms",
  cwe: "CWE-327",
  owasp: "A02:2021",
  languages: ["javascript", "typescript", "python"],
  suggestion: "Use strong cryptographic algorithms (SHA-256+, bcrypt, crypto.getRandomValues)",

  scan(ctx: ScanContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const ast = ctx.ast as AST | null;

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];

      for (const { name, pattern } of INSECURE_CRYPTO_PATTERNS) {
        if (!pattern.test(line)) continue;

        const lineNum = i + 1;
        let confirmed = true;

        // AST verification for JS/TS
        if (ast && (ctx.language === "javascript" || ctx.language === "typescript")) {
          if (name === "MD5 usage") {
            confirmed = hasCreateHashAtLine(ast, lineNum, "md5");
          } else if (name === "SHA1 usage") {
            confirmed = hasCreateHashAtLine(ast, lineNum, "sha1");
          } else if (name === "Math.random for security") {
            confirmed = hasMathRandomAtLine(ast, lineNum);
          }
          // Weak cipher: regex is sufficient, no extra AST check needed
        }

        if (!confirmed) continue;

        // Context-aware confidence for MD5/SHA1:
        // If surrounding code suggests non-password usage (file checksum, ETag, cache key),
        // lower confidence to "medium" to reduce false positives
        let confidence: "high" | "medium" | "low" = "high";
        if (name === "MD5 usage" || name === "SHA1 usage") {
          const surroundingContext = ctx.lines.slice(Math.max(0, i - 3), Math.min(ctx.lines.length, i + 4)).join(" ").toLowerCase();
          const isPasswordContext = /password|passwd|secret|token|credential|auth/.test(surroundingContext);
          const isChecksumContext = /checksum|file|buffer|etag|cache|digest|fingerprint|integrity/.test(surroundingContext);
          if (isChecksumContext && !isPasswordContext) {
            confidence = "medium";
          }
        }

        vulnerabilities.push({
          ruleId: this.id,
          ruleName: this.name,
          severity: this.severity,
          message: `${name} — insecure cryptographic method`,
          filePath: ctx.filePath,
          line: lineNum,
          column: 1,
          snippet: line.trim(),
          cwe: this.cwe,
          owasp: this.owasp,
          suggestion: this.suggestion,
          confidence,
        });
      }
    }

    return vulnerabilities;
  },
};
