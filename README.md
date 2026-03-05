# VEXLIT

AI-powered code security vulnerability scanner with AST-based analysis and SARIF output.

VEXLIT detects security vulnerabilities in JavaScript, TypeScript, and Python using a hybrid Regex + AST approach that minimizes false positives.

## Features

- **22 security rules** covering OWASP Top 10 and CWE
- **AST-based analysis** for JavaScript/TypeScript (regex fallback for Python)
- **SARIF 2.1.0 output** for GitHub Code Scanning integration
- **LLM verification** via Claude API for secondary analysis
- **GitHub Action** for CI/CD integration
- **Configurable** via `vexlit.config.js` or `.vexlitrc.json`

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

| ID | Rule | Severity | CWE | OWASP |
|---|---|---|---|---|
| VEXLIT-001 | Hardcoded Secrets | critical | CWE-798 | A02:2021 |
| VEXLIT-002 | SQL Injection | critical | CWE-89 | A03:2021 |
| VEXLIT-003 | XSS | critical | CWE-79 | A03:2021 |
| VEXLIT-004 | Insecure Crypto | warning | CWE-327 | A02:2021 |
| VEXLIT-006 | Open Redirect | warning | CWE-601 | A01:2021 |
| VEXLIT-007 | JWT Hardcoded Secret | critical | CWE-798 | A02:2021 |
| VEXLIT-008 | JWT None Algorithm | critical | CWE-327 | A02:2021 |
| VEXLIT-009 | Function Constructor | warning | CWE-95 | A03:2021 |
| VEXLIT-010 | Prototype Pollution | warning | CWE-1321 | A03:2021 |
| VEXLIT-011 | NoSQL Injection | critical | CWE-943 | A03:2021 |
| VEXLIT-012 | SSRF | warning | CWE-918 | A10:2021 |
| VEXLIT-013 | Insecure Cookie | warning | CWE-614 | A05:2021 |
| VEXLIT-014 | CORS Misconfiguration | warning | CWE-942 | A05:2021 |
| VEXLIT-015 | ReDoS | warning | CWE-1333 | A06:2021 |
| VEXLIT-016 | Information Exposure | warning | CWE-209 | A04:2021 |
| VEXLIT-017 | Insecure TLS | critical | CWE-295 | A07:2021 |
| VEXLIT-018 | Timing Attack | warning | CWE-208 | A02:2021 |
| VEXLIT-019 | Debugger Statement | info | CWE-489 | A05:2021 |
| VEXLIT-020 | Unsafe Deserialization | critical | CWE-502 | A08:2021 |
| VEXLIT-021 | Path Traversal | critical | CWE-22 | A01:2021 |
| VEXLIT-022 | Command Injection | critical | CWE-78 | A03:2021 |

## GitHub Action

Add VEXLIT to your CI/CD pipeline:

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

## SARIF Output

VEXLIT generates SARIF 2.1.0 compatible output for integration with GitHub Code Scanning:

```bash
vexlit scan . --sarif > results.sarif
```

Upload to GitHub:

```bash
# Via GitHub CLI
gh api -X POST /repos/{owner}/{repo}/code-scanning/sarifs \
  -f "sarif=$(gzip -c results.sarif | base64)"
```

Or use the GitHub Action with `upload-sarif: true` for automatic upload.

## Configuration

Create `vexlit.config.js` in your project root:

```js
export default {
  languages: ["javascript", "typescript"],
  ignore: ["vendor/", "generated/"],
  rules: {
    "VEXLIT-019": false,           // Disable a rule
    "VEXLIT-004": { severity: "critical" }, // Override severity
  },
};
```

Or use `.vexlitrc.json`:

```json
{
  "languages": ["javascript", "typescript", "python"],
  "rules": {
    "VEXLIT-019": false
  }
}
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

Use Claude AI for secondary vulnerability analysis to reduce false positives:

```bash
# Set API key
export ANTHROPIC_API_KEY=sk-ant-...

# Run with LLM verification
vexlit scan . --llm
```

LLM verification analyzes each finding in context and filters out false positives.

## Programmatic API

```typescript
import { scan, scanFile, RuleEngine, allRules } from "@vexlit/core";

// Scan a directory
const results = scan({ paths: ["./src"] });

// Scan a single file
const result = scanFile("./src/app.ts");

// Use the rule engine directly
const engine = new RuleEngine();
const ctx = engine.createContext("app.ts", code, "typescript");
const vulns = engine.execute("app.ts", code, "typescript");
```

## License

MIT
