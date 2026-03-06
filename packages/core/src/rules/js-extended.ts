import type { Rule, Vulnerability, ScanContext, Severity, Confidence } from "../types.js";

interface JsRulePattern {
  id: string;
  name: string;
  severity: Severity;
  confidence: Confidence;
  description: string;
  cwe: string;
  owasp: string;
  suggestion: string;
  pattern: RegExp;
  antiPattern?: RegExp;
}

// ---------- React Security ----------
const react: JsRulePattern[] = [
  {
    id: "VEXLIT-030",
    name: "React javascript: URI",
    confidence: "high", severity: "critical",
    description: "javascript: protocol in React href enables XSS attacks",
    cwe: "CWE-79",
    owasp: "A03:2021",
    suggestion: "Never use javascript: URIs. Use onClick handlers instead",
    pattern: /href\s*=\s*[{(]?\s*["'`]javascript:/i,
  },
  {
    id: "VEXLIT-031",
    name: "React target=_blank without rel",
    confidence: "medium", severity: "warning",
    description: "target=\"_blank\" without rel=\"noopener noreferrer\" exposes window.opener",
    cwe: "CWE-1022",
    owasp: "A05:2021",
    suggestion: "Add rel=\"noopener noreferrer\" to links with target=\"_blank\"",
    pattern: /target\s*=\s*["']_blank["']/,
    antiPattern: /rel\s*=\s*["'][^"']*noopener/,
  },
  {
    id: "VEXLIT-032",
    name: "React UNSAFE lifecycle method",
    confidence: "medium", severity: "warning",
    description: "UNSAFE_ lifecycle methods may cause security issues and are deprecated",
    cwe: "CWE-477",
    owasp: "A06:2021",
    suggestion: "Migrate to safe lifecycle alternatives (useEffect, componentDidMount)",
    pattern: /UNSAFE_(?:componentWillMount|componentWillReceiveProps|componentWillUpdate)\s*\(/,
  },
  {
    id: "VEXLIT-033",
    name: "React useEffect missing cleanup",
    confidence: "low", severity: "info",
    description: "useEffect with subscriptions or timers should return a cleanup function",
    cwe: "CWE-404",
    owasp: "A06:2021",
    suggestion: "Return a cleanup function from useEffect to prevent memory leaks",
    pattern: /useEffect\s*\(\s*(?:async\s*)?\(\s*\)\s*=>\s*\{[^}]*(?:setInterval|addEventListener|subscribe|WebSocket)\b/,
    antiPattern: /return\s/,
  },
];

// ---------- Next.js Security ----------
const nextjs: JsRulePattern[] = [
  {
    id: "VEXLIT-034",
    name: "Next.js NEXT_PUBLIC sensitive data",
    confidence: "high", severity: "critical",
    description: "NEXT_PUBLIC_ variables are exposed to the browser and should not contain secrets",
    cwe: "CWE-200",
    owasp: "A01:2021",
    suggestion: "Remove NEXT_PUBLIC_ prefix from secret environment variables",
    pattern: /NEXT_PUBLIC_(?:SECRET|PASSWORD|TOKEN|PRIVATE|API_SECRET|DB_|DATABASE|SUPABASE_SERVICE)/i,
  },
  {
    id: "VEXLIT-035",
    name: "Next.js API route without auth check",
    confidence: "medium", severity: "warning",
    description: "API route handler without authentication check may expose data",
    cwe: "CWE-306",
    owasp: "A07:2021",
    suggestion: "Add authentication/authorization checks at the beginning of API route handlers",
    pattern: /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)\s*\(/,
    antiPattern: /auth|session|getUser|getToken|verify|middleware|unauthorized|401/i,
  },
  {
    id: "VEXLIT-036",
    name: "Next.js unsafe redirect",
    confidence: "medium", severity: "warning",
    description: "Unvalidated redirect destination may lead to open redirect attacks",
    cwe: "CWE-601",
    owasp: "A01:2021",
    suggestion: "Validate redirect destinations against an allowlist of trusted URLs",
    pattern: /(?:redirect|NextResponse\.redirect)\s*\(\s*(?:req\.|request\.|params\.|query\.|searchParams)/,
  },
  {
    id: "VEXLIT-037",
    name: "Next.js server action data exposure",
    confidence: "medium", severity: "warning",
    description: "Server component passing sensitive data to client components",
    cwe: "CWE-200",
    owasp: "A01:2021",
    suggestion: "Filter sensitive fields before passing data to client components",
    pattern: /['"]use server['"][\s\S]{0,500}(?:password|secret|token|apiKey|private_key)\s*[,:]/i,
  },
];

// ---------- Node.js Security ----------
const nodejs: JsRulePattern[] = [
  {
    id: "VEXLIT-038",
    name: "Node.js Buffer() constructor",
    confidence: "medium", severity: "warning",
    description: "Buffer() constructor is deprecated and can cause security issues",
    cwe: "CWE-131",
    owasp: "A06:2021",
    suggestion: "Use Buffer.alloc(), Buffer.allocUnsafe(), or Buffer.from() instead",
    pattern: /new\s+Buffer\s*\(/,
  },
  {
    id: "VEXLIT-039",
    name: "Node.js HTTP without TLS",
    confidence: "medium", severity: "warning",
    description: "Using http.createServer instead of https exposes data in transit",
    cwe: "CWE-319",
    owasp: "A02:2021",
    suggestion: "Use https.createServer or deploy behind a TLS-terminating proxy",
    pattern: /http\.createServer\s*\(/,
    antiPattern: /https|proxy|localhost|127\.0\.0\.1|test/i,
  },
  {
    id: "VEXLIT-040",
    name: "Node.js fs chmod 0777",
    confidence: "high", severity: "critical",
    description: "Setting file permissions to 0777 gives everyone read/write/execute access",
    cwe: "CWE-732",
    owasp: "A01:2021",
    suggestion: "Use restrictive permissions like 0600 (owner-only) or 0644",
    pattern: /(?:chmod|chmodSync|writeFile|writeFileSync)\s*\([^)]*(?:0o?777|0o?766|0o?776)/,
  },
  {
    id: "VEXLIT-041",
    name: "Node.js unsafe regex from input",
    confidence: "high", severity: "critical",
    description: "Creating RegExp from user input enables ReDoS attacks",
    cwe: "CWE-1333",
    owasp: "A03:2021",
    suggestion: "Sanitize user input before using in RegExp, or use a safe regex library",
    pattern: /new\s+RegExp\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|input|user)/,
  },
  {
    id: "VEXLIT-042",
    name: "Node.js child_process with shell",
    confidence: "high", severity: "critical",
    description: "Using shell option in child_process enables command injection",
    cwe: "CWE-78",
    owasp: "A03:2021",
    suggestion: "Avoid shell: true. Use execFile or spawn without shell option",
    pattern: /(?:spawn|execFile)\s*\([^)]*\{[^}]*shell\s*:\s*true/,
  },
  {
    id: "VEXLIT-043",
    name: "Node.js unhandled rejection",
    confidence: "medium", severity: "warning",
    description: "Missing unhandledRejection handler can crash the process or leak errors",
    cwe: "CWE-755",
    owasp: "A09:2021",
    suggestion: "Add process.on('unhandledRejection', handler) to handle unexpected errors",
    pattern: /\.catch\s*\(\s*\)/,
  },
];

// ---------- Express Security ----------
const express: JsRulePattern[] = [
  {
    id: "VEXLIT-044",
    name: "Express missing helmet",
    confidence: "medium", severity: "warning",
    description: "Express app without helmet middleware is missing security headers",
    cwe: "CWE-693",
    owasp: "A05:2021",
    suggestion: "Add helmet middleware: app.use(helmet())",
    pattern: /(?:express|fastify)\s*\(\s*\)/,
    antiPattern: /helmet/,
  },
  {
    id: "VEXLIT-045",
    name: "Express no body size limit",
    confidence: "medium", severity: "warning",
    description: "Missing body parser size limit enables denial-of-service via large payloads",
    cwe: "CWE-400",
    owasp: "A05:2021",
    suggestion: "Set body parser limit: express.json({ limit: '1mb' })",
    pattern: /(?:express\.json|express\.urlencoded|bodyParser\.json|bodyParser\.urlencoded)\s*\(\s*\)/,
  },
  {
    id: "VEXLIT-046",
    name: "Express static dotfiles",
    confidence: "medium", severity: "warning",
    description: "Serving static files may expose dotfiles like .env or .git",
    cwe: "CWE-538",
    owasp: "A01:2021",
    suggestion: "Configure dotfiles option: express.static(path, { dotfiles: 'deny' })",
    pattern: /express\.static\s*\(\s*["'`][^"'`]+["'`]\s*\)/,
    antiPattern: /dotfiles/,
  },
  {
    id: "VEXLIT-047",
    name: "Express session insecure config",
    confidence: "high", severity: "critical",
    description: "Session middleware without secure configuration exposes session tokens",
    cwe: "CWE-614",
    owasp: "A02:2021",
    suggestion: "Set secure cookie options: { secure: true, httpOnly: true, sameSite: 'strict' }",
    pattern: /session\s*\(\s*\{[\s\S]{0,200}secret\s*:/,
    antiPattern: /secure\s*:\s*true/,
  },
  {
    id: "VEXLIT-048",
    name: "Express error stack exposure",
    confidence: "medium", severity: "warning",
    description: "Sending error stack traces to clients exposes internal details",
    cwe: "CWE-209",
    owasp: "A04:2021",
    suggestion: "Never send err.stack to clients in production. Use generic error messages",
    pattern: /(?:res\.(?:json|send|status))\s*\([^)]*(?:err\.stack|error\.stack|\.stack)/,
  },
];

// ---------- DOM / Browser Security ----------
const dom: JsRulePattern[] = [
  {
    id: "VEXLIT-049",
    name: "postMessage without origin check",
    confidence: "high", severity: "critical",
    description: "Handling postMessage events without verifying origin enables XSS",
    cwe: "CWE-346",
    owasp: "A07:2021",
    suggestion: "Always verify event.origin before processing postMessage data",
    pattern: /addEventListener\s*\(\s*["']message["']/,
    antiPattern: /(?:event|e|msg)\.origin/,
  },
  {
    id: "VEXLIT-050",
    name: "localStorage sensitive data",
    confidence: "medium", severity: "warning",
    description: "Storing sensitive data in localStorage is accessible to XSS attacks",
    cwe: "CWE-922",
    owasp: "A04:2021",
    suggestion: "Use httpOnly cookies for tokens. Never store secrets in localStorage",
    pattern: /localStorage\.setItem\s*\(\s*["'`](?:token|auth|jwt|session|password|secret|api[_-]?key)/i,
  },
  {
    id: "VEXLIT-051",
    name: "window.open without noopener",
    confidence: "medium", severity: "warning",
    description: "window.open without noopener gives the new window access to window.opener",
    cwe: "CWE-1022",
    owasp: "A05:2021",
    suggestion: "Add 'noopener,noreferrer' to window.open features parameter",
    pattern: /window\.open\s*\(\s*[^,)]+\s*(?:\)|,\s*["'][^"']*["']\s*\))/,
    antiPattern: /noopener/,
  },
  {
    id: "VEXLIT-052",
    name: "document.domain manipulation",
    confidence: "high", severity: "critical",
    description: "Setting document.domain relaxes same-origin policy and enables attacks",
    cwe: "CWE-346",
    owasp: "A07:2021",
    suggestion: "Do not set document.domain. Use CORS or postMessage for cross-origin communication",
    pattern: /document\.domain\s*=/,
  },
  {
    id: "VEXLIT-053",
    name: "URL scheme bypass",
    confidence: "high", severity: "critical",
    description: "URL validation that doesn't check scheme allows javascript: or data: URIs",
    cwe: "CWE-79",
    owasp: "A03:2021",
    suggestion: "Validate URL scheme against allowlist (http:, https:) before use",
    pattern: /(?:location\.href|window\.location|location\.assign|location\.replace)\s*=\s*(?:req\.|request\.|params\.|query\.|input|user)/,
  },
];

// ---------- Authentication / Authorization ----------
const authSecurity: JsRulePattern[] = [
  {
    id: "VEXLIT-054",
    name: "Weak password validation",
    confidence: "medium", severity: "warning",
    description: "Password validation regex is too permissive (short minimum length)",
    cwe: "CWE-521",
    owasp: "A07:2021",
    suggestion: "Require minimum 8 characters with mixed case, numbers, and special characters",
    pattern: /password.*\.length\s*(?:>=?|>)\s*[1-5]\b/i,
  },
  {
    id: "VEXLIT-055",
    name: "Missing CSRF token",
    confidence: "medium", severity: "warning",
    description: "Form submission without CSRF protection enables cross-site request forgery",
    cwe: "CWE-352",
    owasp: "A01:2021",
    suggestion: "Include CSRF token in forms and validate on the server",
    pattern: /method\s*=\s*["'](?:POST|PUT|DELETE|PATCH)["']/i,
    antiPattern: /csrf|_token|xsrf|csrfmiddlewaretoken/i,
  },
  {
    id: "VEXLIT-056",
    name: "JWT stored in localStorage",
    confidence: "medium", severity: "warning",
    description: "JWTs in localStorage are vulnerable to XSS. Use httpOnly cookies instead",
    cwe: "CWE-922",
    owasp: "A04:2021",
    suggestion: "Store JWTs in httpOnly, secure cookies instead of localStorage",
    pattern: /localStorage\.setItem\s*\([^)]*(?:jwt|token|access_token|id_token|refresh_token)/i,
  },
  {
    id: "VEXLIT-057",
    name: "Timing-safe comparison missing",
    confidence: "medium", severity: "warning",
    description: "String comparison for secrets is vulnerable to timing attacks",
    cwe: "CWE-208",
    owasp: "A02:2021",
    suggestion: "Use crypto.timingSafeEqual() for comparing secrets, tokens, or hashes",
    pattern: /(?:apiKey|token|secret|hash|signature|hmac)\s*(?:===?|!==?)\s*(?:req\.|request\.|body\.|params\.|query\.)/i,
    antiPattern: /timingSafeEqual/,
  },
];

// ---------- Configuration Security ----------
const config: JsRulePattern[] = [
  {
    id: "VEXLIT-058",
    name: "Debug mode in production",
    confidence: "medium", severity: "warning",
    description: "Debug mode enabled in production exposes sensitive information",
    cwe: "CWE-489",
    owasp: "A05:2021",
    suggestion: "Disable debug mode in production. Use NODE_ENV to control debug settings",
    pattern: /(?:debug|DEBUG)\s*[:=]\s*(?:true|1|["'](?:true|1|on|yes)["'])/,
    antiPattern: /NODE_ENV|process\.env|test|development/i,
  },
  {
    id: "VEXLIT-059",
    name: "Verbose error logging",
    confidence: "low", severity: "info",
    description: "Logging full error objects may expose stack traces and internal paths",
    cwe: "CWE-532",
    owasp: "A09:2021",
    suggestion: "Log only error messages in production, not full error objects or stacks",
    pattern: /console\.(?:log|error|warn)\s*\([^)]*(?:err\b|error\b)[^)]*\)/,
    antiPattern: /\.message|\.code/,
  },
  {
    id: "VEXLIT-060",
    name: "Hardcoded IP address",
    confidence: "low", severity: "info",
    description: "Hardcoded IP addresses make infrastructure changes difficult and may leak internal topology",
    cwe: "CWE-547",
    owasp: "A05:2021",
    suggestion: "Use environment variables or configuration files for IP addresses",
    pattern: /["'`](?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})["'`]/,
    antiPattern: /test|mock|example|localhost/i,
  },
  {
    id: "VEXLIT-061",
    name: "Disabled SSL verification",
    confidence: "high", severity: "critical",
    description: "Disabling SSL certificate verification enables man-in-the-middle attacks",
    cwe: "CWE-295",
    owasp: "A07:2021",
    suggestion: "Never disable SSL verification in production. Fix certificate issues instead",
    pattern: /(?:rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED)\s*[:=]\s*(?:false|0|["']0["'])/,
  },
];

// ---------- Data Handling ----------
const dataHandling: JsRulePattern[] = [
  {
    id: "VEXLIT-062",
    name: "JSON.parse without try-catch",
    confidence: "low", severity: "info",
    description: "JSON.parse without error handling can crash on malformed input",
    cwe: "CWE-20",
    owasp: "A03:2021",
    suggestion: "Wrap JSON.parse in try-catch when parsing user-provided data",
    pattern: /JSON\.parse\s*\(\s*(?:req\.|request\.|body|input|data|user|params)/,
    antiPattern: /try\s*\{/,
  },
  {
    id: "VEXLIT-063",
    name: "Unvalidated file upload type",
    confidence: "high", severity: "critical",
    description: "Accepting file uploads without MIME type validation enables arbitrary file upload",
    cwe: "CWE-434",
    owasp: "A04:2021",
    suggestion: "Validate file MIME type and extension before processing uploads",
    pattern: /(?:multer|formidable|busboy|multiparty)\s*\(/,
    antiPattern: /fileFilter|mimetype|allowedTypes|accept/i,
  },
  {
    id: "VEXLIT-064",
    name: "Template literal in SQL query",
    confidence: "high", severity: "critical",
    description: "Using template literals in SQL queries without parameterization enables SQL injection",
    cwe: "CWE-89",
    owasp: "A03:2021",
    suggestion: "Use parameterized queries with placeholder values",
    pattern: /\.(?:query|execute|run)\s*\(\s*`[^`]*\$\{/,
    antiPattern: /prepared|parameterized/i,
  },
  {
    id: "VEXLIT-065",
    name: "Unsafe object spread from request",
    confidence: "medium", severity: "warning",
    description: "Spreading request body directly into database queries enables mass assignment",
    cwe: "CWE-915",
    owasp: "A08:2021",
    suggestion: "Explicitly pick allowed fields instead of spreading entire request body",
    pattern: /(?:\.create|\.update|\.insert|\.upsert)\s*\(\s*(?:\{[^}]*\.\.\.(?:req\.body|body|data))/,
  },
  {
    id: "VEXLIT-066",
    name: "Logging sensitive data",
    confidence: "medium", severity: "warning",
    description: "Logging sensitive data (passwords, tokens) may expose it in log files",
    cwe: "CWE-532",
    owasp: "A09:2021",
    suggestion: "Redact sensitive fields before logging. Never log passwords or tokens",
    pattern: /console\.(?:log|info|warn|error|debug)\s*\([^)]*(?:password|passwd|secret|token|apiKey|creditCard|ssn|authorization)/i,
    antiPattern: /redact|mask|sanitize|\*{3,}/i,
  },
  {
    id: "VEXLIT-067",
    name: "Unsafe HTML template",
    confidence: "high", severity: "critical",
    description: "Interpolating user input into HTML templates without escaping enables XSS",
    cwe: "CWE-79",
    owasp: "A03:2021",
    suggestion: "Use a template engine with auto-escaping or escape HTML entities manually",
    pattern: /`<[^>]*\$\{(?:req\.|request\.|query\.|params\.|body\.|user|input)/,
  },
  {
    id: "VEXLIT-068",
    name: "Missing input length validation",
    confidence: "low", severity: "info",
    description: "Not validating input length can lead to denial-of-service or buffer overflow",
    cwe: "CWE-20",
    owasp: "A03:2021",
    suggestion: "Validate input length before processing. Set maximum length limits",
    pattern: /(?:req\.body|req\.query|req\.params)\.\w+\s*(?:&&|\|\||;)/,
    antiPattern: /\.length|maxLength|max_length|\.slice|\.substring|limit/i,
  },
  {
    id: "VEXLIT-069",
    name: "Unsafe iframe embedding",
    confidence: "medium", severity: "warning",
    description: "Embedding untrusted content in iframes without sandbox may enable attacks",
    cwe: "CWE-1021",
    owasp: "A05:2021",
    suggestion: "Add sandbox attribute to iframes loading untrusted content",
    pattern: /<iframe[^>]*src\s*=\s*[{(]?\s*(?:\$\{|[+])/,
    antiPattern: /sandbox/i,
  },
];

const allJsPatterns: JsRulePattern[] = [
  ...react,
  ...nextjs,
  ...nodejs,
  ...express,
  ...dom,
  ...authSecurity,
  ...config,
  ...dataHandling,
];

export const jsExtendedRules: Rule[] = allJsPatterns.map((p) => ({
  id: p.id,
  name: p.name,
  severity: p.severity,
  description: p.description,
  cwe: p.cwe,
  owasp: p.owasp,
  languages: ["javascript", "typescript"] as const,
  suggestion: p.suggestion,

  scan(ctx: ScanContext): Vulnerability[] {
    const vulns: Vulnerability[] = [];

    // File-level antiPattern check (for rules like "missing helmet" that check whole file)
    if (p.antiPattern && p.id === "VEXLIT-044") {
      // For helmet: only flag if entire file has no mention of helmet
      const hasAntiPattern = p.antiPattern.test(ctx.content);
      if (hasAntiPattern) return vulns;
    }

    for (let i = 0; i < ctx.lines.length; i++) {
      const line = ctx.lines[i];

      if (!p.pattern.test(line)) continue;

      // Skip comments
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;

      // Line-level antiPattern: if the same line has the fix, skip
      if (p.antiPattern && p.id !== "VEXLIT-044") {
        // Check surrounding context (current line + next 3 lines)
        const context = ctx.lines.slice(i, Math.min(i + 4, ctx.lines.length)).join(" ");
        if (p.antiPattern.test(context)) continue;
      }

      vulns.push({
        ruleId: this.id,
        ruleName: this.name,
        severity: this.severity,
        message: p.description,
        filePath: ctx.filePath,
        line: i + 1,
        column: line.search(p.pattern) + 1,
        snippet: line.trim(),
        cwe: p.cwe,
        owasp: p.owasp,
        suggestion: p.suggestion,
        confidence: p.confidence,
      });
    }

    return vulns;
  },
}));
