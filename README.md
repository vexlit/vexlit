# VEXLIT

AI-powered code security vulnerability scanner with AST-based analysis, tree-sitter parsing, and 263 security rules.

VEXLIT detects security vulnerabilities in JavaScript, TypeScript, and Python using a hybrid Regex + AST approach with tree-sitter WASM parsing that minimizes false positives.

## Features

- **263 security rules** — 23 AST-verified rules, 40 JS extended rules, 200 secret patterns
- **Tree-sitter AST parsing** for JavaScript, TypeScript, and Python (WASM-based)
- **Confidence scoring** — high/medium/low per vulnerability for FP filtering
- **SARIF 2.1.0 output** for GitHub Code Scanning integration
- **Web dashboard** — GitHub OAuth, scan history, trend charts, AI explanations
- **AI verification** via Claude API — explains vulnerabilities, suggests fixes, generates reports
- **Live demo** on the landing page — paste code and scan instantly
- **Configurable** via `vexlit.config.js` or `.vexlitrc.json`

## Web Dashboard

**[https://vexlit.vercel.app](https://vexlit.vercel.app)**

- Connect your GitHub repository and scan in one click
- Severity donut charts, vulnerability trend graphs
- Filter by severity, file, rule, or "exploitable only" (critical + high confidence)
- AI Explain / AI Fix buttons per vulnerability
- SARIF download, AI security report generation
- Dark / light mode toggle

## Installation

```bash
npm install -g @vexlit/cli
```

Or use npx without installing:

```bash
npx @vexlit/cli scan .
```

## Quick Start

```bash
# Scan current directory
vexlit scan .

# Scan specific files or directories
vexlit scan src/ lib/utils.ts

# Output as JSON
vexlit scan . --json

# Output as SARIF (for GitHub Security)
vexlit scan . --sarif > results.sarif

# Enable LLM verification
vexlit scan . --llm --api-key sk-ant-...
```

## Rules

### AST-Verified Rules (23)

| ID | Rule | Severity | CWE |
|---|---|---|---|
| VEXLIT-001 | Hardcoded Secrets | critical | CWE-798 |
| VEXLIT-002 | SQL Injection | critical | CWE-89 |
| VEXLIT-003 | XSS | critical | CWE-79 |
| VEXLIT-004 | Insecure Crypto | warning | CWE-327 |
| VEXLIT-006 | Open Redirect | warning | CWE-601 |
| VEXLIT-007 | JWT Hardcoded Secret | critical | CWE-798 |
| VEXLIT-008 | JWT None Algorithm | critical | CWE-327 |
| VEXLIT-009 | Function Constructor | warning | CWE-95 |
| VEXLIT-010 | Prototype Pollution | critical | CWE-1321 |
| VEXLIT-011 | NoSQL Injection | critical | CWE-943 |
| VEXLIT-012 | SSRF | warning | CWE-918 |
| VEXLIT-013 | Insecure Cookie | warning | CWE-614 |
| VEXLIT-014 | CORS Misconfiguration | warning | CWE-942 |
| VEXLIT-015 | ReDoS | warning | CWE-1333 |
| VEXLIT-016 | Information Exposure | warning | CWE-209 |
| VEXLIT-017 | Insecure TLS | critical | CWE-295 |
| VEXLIT-018 | Timing Attack | warning | CWE-208 |
| VEXLIT-019 | Debugger Statement | info | CWE-489 |
| VEXLIT-020 | Unsafe Deserialization | critical | CWE-502 |
| VEXLIT-021 | Path Traversal | critical | CWE-22 |
| VEXLIT-022 | Command Injection | critical | CWE-78 |
| VEXLIT-023 | Eval Injection | critical | CWE-95 |

### JS Extended Rules (40)

VEXLIT-030 through VEXLIT-069 covering additional patterns: dangerouslySetInnerHTML, insecure randomness, helmet missing, body parser limits, unsafe regex, and more.

### Secret Patterns (200)

200 declarative patterns across 28 categories detecting API keys and tokens for:

AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, Twilio, SendGrid, Firebase, Supabase, MongoDB, Redis, Docker, Terraform, Jenkins, CircleCI, Datadog, Sentry, Algolia, PagerDuty, Linear, Jira, Zendesk, New Relic, Mixpanel, Cloudinary, npm, PyPI, and more.

## Architecture

```
packages/
  core/     # Scanner engine — rules, AST parser, tree-sitter, secret patterns
  cli/      # Command-line interface
  web/      # Next.js 16 web dashboard (Supabase, Vercel)
```

- **Hybrid detection**: Regex prefilter → AST verification (tree-sitter WASM or @typescript-eslint)
- **Confidence scoring**: Each vulnerability tagged high/medium/low based on FP risk
- **Deduplication**: Same file:line → keep highest severity, prefer longer ruleId
- **Async engine**: `RuleEngine.execute()` is async for tree-sitter WASM initialization
- **Graceful fallback**: If tree-sitter fails to load, regex-only rules still work

## GitHub Action

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: vexlit/vexlit@v1
        with:
          paths: "."
          fail-on: "critical"
          upload-sarif: "true"
```

### Action Inputs

| Input | Default | Description |
|---|---|---|
| `paths` | `.` | Paths to scan (space-separated) |
| `format` | `sarif` | Output format: table, json, sarif |
| `fail-on` | `critical` | Minimum severity to fail: critical, warning, info, none |
| `upload-sarif` | `true` | Upload SARIF to GitHub Code Scanning |
| `sarif-file` | `vexlit-results.sarif` | SARIF output file path |

### Action Outputs

| Output | Description |
|---|---|
| `total` | Total vulnerabilities found |
| `critical` | Number of critical vulnerabilities |
| `warning` | Number of warning vulnerabilities |
| `info` | Number of info vulnerabilities |
| `sarif-file` | Path to generated SARIF file |

## Configuration

Create `vexlit.config.js` in your project root:

```js
export default {
  languages: ["javascript", "typescript", "python"],
  ignore: ["vendor/", "generated/"],
  rules: {
    "VEXLIT-019": false,           // Disable a rule
    "VEXLIT-004": { severity: "critical" }, // Override severity
  },
};
```

### Ignore Patterns

Create `.vexlitignore` in your project root:

```
vendor/
*.generated.ts
test-fixtures/
```

Default ignores: `node_modules`, `.git`, `dist`, `build`, `.next`, `__pycache__`, `.venv`, `coverage`

## LLM Verification

Use Claude AI for secondary vulnerability analysis:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
vexlit scan . --llm
```

LLM verification analyzes each finding in context, filters false positives, and adjusts severity.

## Programmatic API

```typescript
import { scan, scanFile, RuleEngine } from "@vexlit/core";

// Scan a directory
const results = await scan({ paths: ["./src"] });

// Scan a single file
const result = await scanFile("./src/app.ts");

// Use the rule engine directly
const engine = new RuleEngine();
const vulns = await engine.execute("app.ts", code, "typescript");
```

## Tech Stack

| Layer | Technology |
|---|---|
| Scanner | TypeScript, tree-sitter (WASM), @typescript-eslint |
| CLI | Commander.js, SARIF 2.1.0 |
| Web | Next.js 16, React 19, Tailwind CSS 4, Framer Motion |
| Auth & DB | Supabase (PostgreSQL, GitHub OAuth) |
| AI | Claude API (Anthropic SDK) |
| Charts | Recharts (lazy loaded) |
| Deploy | Vercel (Hobby) |

## License

MIT
