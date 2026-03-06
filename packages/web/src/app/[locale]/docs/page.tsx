import Link from "next/link";
import { LandingNav } from "@/components/landing/landing-nav";
import { getTranslations } from "next-intl/server";

/* ── Data ── */

const INSTALL_METHODS = [
  { label: "npm", command: "npm install -g @vexlit/cli" },
  { label: "npx", command: "npx @vexlit/cli scan ." },
];

const OUTPUT_LINES = [
  { type: "header" as const, text: "VEXLIT Security Scanner v0.1.0" },
  { type: "info" as const, text: "Scanning 47 files..." },
  { type: "blank" as const, text: "" },
  { type: "critical" as const, text: "CRITICAL  VEXLIT-002  SQL Injection           api/users.js:42" },
  { type: "critical" as const, text: "CRITICAL  VEXLIT-001  Hardcoded Secret        config/auth.ts:12" },
  { type: "warning" as const, text: "WARNING   VEXLIT-012  SSRF                    lib/fetch.ts:28" },
  { type: "info" as const, text: "INFO      VEXLIT-019  Debugger Statement      utils/debug.js:5" },
  { type: "blank" as const, text: "" },
  { type: "summary" as const, text: "Found 4 vulnerabilities (2 critical, 1 warning, 1 info)" },
  { type: "time" as const, text: "Scan completed in 2.4s" },
];

const CONFIG_EXAMPLE = `export default {
  languages: ["javascript", "typescript", "python"],
  ignore: ["vendor/", "generated/"],
  rules: {
    "VEXLIT-019": false,           // Disable a rule
    "VEXLIT-004": { severity: "critical" }, // Override severity
  },
};`;

const GITHUB_ACTION = `name: Security Scan

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
          upload-sarif: "true"`;

const API_EXAMPLE = `import { scan, scanFile, RuleEngine } from "@vexlit/core";

// Scan a directory
const results = await scan({ paths: ["./src"] });

// Scan a single file
const result = await scanFile("./src/app.ts");

// Use the rule engine directly
const engine = new RuleEngine();
const vulns = await engine.execute("app.ts", code, "typescript");`;

/* ── Helpers ── */

function CodeBlock({ code, lang, filename }: { code: string; lang?: string; filename?: string }) {
  return (
    <div className="bg-gray-950 border border-gray-800 rounded-xl overflow-hidden">
      {filename && (
        <div className="flex items-center gap-2 px-4 py-2 border-b border-gray-800 bg-gray-900/50">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-gray-700" />
            <span className="w-3 h-3 rounded-full bg-gray-700" />
            <span className="w-3 h-3 rounded-full bg-gray-700" />
          </div>
          <span className="text-gray-500 text-xs font-mono ml-2">{filename}</span>
        </div>
      )}
      <pre className="p-4 overflow-x-auto">
        <code className={`text-sm leading-relaxed ${lang === "bash" ? "text-green-400" : "text-gray-300"}`}>
          {code}
        </code>
      </pre>
    </div>
  );
}

function TerminalOutput() {
  return (
    <div className="bg-gray-950 border border-gray-800 rounded-xl overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-gray-800 bg-gray-900/50">
        <div className="flex gap-1.5">
          <span className="w-3 h-3 rounded-full bg-red-500/80" />
          <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
          <span className="w-3 h-3 rounded-full bg-green-500/80" />
        </div>
        <span className="text-gray-500 text-xs font-mono ml-2">Terminal</span>
      </div>
      <div className="p-4 font-mono text-sm leading-relaxed">
        {OUTPUT_LINES.map((line, i) => {
          if (line.type === "blank") return <div key={i} className="h-4" />;
          const colors: Record<string, string> = {
            header: "text-white font-bold",
            info: "text-blue-400",
            critical: "text-red-400",
            warning: "text-yellow-400",
            summary: "text-white font-semibold",
            time: "text-gray-500",
          };
          return (
            <div key={i} className={colors[line.type]}>
              {line.text}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SectionHeading({ badge, title, description }: { badge: string; title: string; description: string }) {
  return (
    <div className="mb-8">
      <span className="inline-block px-3 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-medium mb-4">
        {badge}
      </span>
      <h2 className="text-2xl md:text-3xl font-bold text-white mb-3">{title}</h2>
      <p className="text-gray-400 max-w-2xl">{description}</p>
    </div>
  );
}

/* ── Page ── */

export default async function DocsPage() {
  const t = await getTranslations("docs");
  const tCommon = await getTranslations("common");
  const tLanding = await getTranslations("landing");

  const COMMANDS = [
    { command: "vexlit scan .", description: t("scanCurrentDir") },
    { command: "vexlit scan src/ lib/utils.ts", description: t("scanSpecific") },
    { command: "vexlit scan . --json", description: t("outputJson") },
    { command: "vexlit scan . --sarif > results.sarif", description: t("exportSarif") },
    { command: "vexlit scan . --llm --api-key sk-ant-...", description: t("enableAi") },
  ];

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      <LandingNav />

      {/* Hero */}
      <section className="max-w-4xl mx-auto px-6 pt-28 pb-12">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-sm mb-6">
          <span className="w-2 h-2 rounded-full bg-red-500" />
          {t("badge")}
        </div>
        <h1 className="text-4xl md:text-5xl font-bold leading-tight tracking-tight mb-4">
          {t("heroTitle1")}{" "}
          <span className="bg-gradient-to-r from-red-500 to-orange-500 bg-clip-text text-transparent">
            {t("heroTitle2")}
          </span>
        </h1>
        <p className="text-lg text-gray-400 max-w-2xl mb-8">{t("heroDescription")}</p>
        <div className="flex flex-wrap gap-3">
          <a
            href="https://www.npmjs.com/package/@vexlit/cli"
            target="_blank"
            rel="noopener noreferrer"
            className="px-5 py-2.5 bg-red-600 rounded-lg text-sm font-medium hover:bg-red-700 transition-colors"
          >
            {t("viewOnNpm")}
          </a>
          <a
            href="https://github.com/vexlit/vexlit"
            target="_blank"
            rel="noopener noreferrer"
            className="px-5 py-2.5 border border-gray-700 rounded-lg text-sm font-medium hover:border-gray-500 transition-colors"
          >
            {t("githubRepo")}
          </a>
        </div>
      </section>

      {/* Installation */}
      <section className="max-w-4xl mx-auto px-6 py-12 border-t border-gray-800">
        <SectionHeading badge={t("installBadge")} title={t("installTitle")} description={t("installDesc")} />
        <div className="grid md:grid-cols-2 gap-4">
          {INSTALL_METHODS.map((m) => (
            <div key={m.label} className="bg-gray-900 border border-gray-800 rounded-xl p-5 hover:border-gray-700 transition-colors">
              <p className="text-gray-400 text-xs font-medium uppercase tracking-wider mb-3">{m.label}</p>
              <code className="text-green-400 text-sm font-mono">{m.command}</code>
            </div>
          ))}
        </div>
      </section>

      {/* Commands */}
      <section className="max-w-4xl mx-auto px-6 py-12 border-t border-gray-800">
        <SectionHeading badge={t("commandsBadge")} title={t("commandsTitle")} description={t("commandsDesc")} />
        <div className="space-y-3">
          {COMMANDS.map((c) => (
            <div key={c.command} className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4 flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-6 hover:border-gray-700 transition-colors">
              <code className="text-green-400 text-sm font-mono whitespace-nowrap flex-shrink-0">$ {c.command}</code>
              <span className="text-gray-500 text-sm">{c.description}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Output */}
      <section className="max-w-4xl mx-auto px-6 py-12 border-t border-gray-800">
        <SectionHeading badge={t("outputBadge")} title={t("outputTitle")} description={t("outputDesc")} />
        <TerminalOutput />
      </section>

      {/* Configuration */}
      <section className="max-w-4xl mx-auto px-6 py-12 border-t border-gray-800">
        <SectionHeading badge={t("configBadge")} title={t("configTitle")} description={t("configDesc")} />
        <CodeBlock code={CONFIG_EXAMPLE} lang="js" filename="vexlit.config.js" />
        <div className="mt-6 bg-gray-900 border border-gray-800 rounded-xl p-5">
          <p className="text-white text-sm font-medium mb-2">{t("defaultIgnored")}</p>
          <p className="text-gray-400 text-sm font-mono">
            node_modules, .git, dist, build, .next, __pycache__, .venv, coverage
          </p>
        </div>
      </section>

      {/* CI/CD */}
      <section className="max-w-4xl mx-auto px-6 py-12 border-t border-gray-800">
        <SectionHeading badge={t("cicdBadge")} title={t("cicdTitle")} description={t("cicdDesc")} />
        <CodeBlock code={GITHUB_ACTION} lang="yaml" filename=".github/workflows/security.yml" />
        <div className="mt-6 grid sm:grid-cols-2 gap-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <p className="text-white text-sm font-medium mb-3">{t("inputs")}</p>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between"><code className="text-gray-400 font-mono">paths</code><span className="text-gray-600">.</span></div>
              <div className="flex justify-between"><code className="text-gray-400 font-mono">format</code><span className="text-gray-600">sarif</span></div>
              <div className="flex justify-between"><code className="text-gray-400 font-mono">fail-on</code><span className="text-gray-600">critical</span></div>
              <div className="flex justify-between"><code className="text-gray-400 font-mono">upload-sarif</code><span className="text-gray-600">true</span></div>
            </div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <p className="text-white text-sm font-medium mb-3">{t("outputs")}</p>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between"><code className="text-gray-400 font-mono">total</code><span className="text-gray-600">{t("totalVulns")}</span></div>
              <div className="flex justify-between"><code className="text-gray-400 font-mono">critical</code><span className="text-gray-600">{t("criticalCount")}</span></div>
              <div className="flex justify-between"><code className="text-gray-400 font-mono">sarif-file</code><span className="text-gray-600">{t("sarifPath")}</span></div>
            </div>
          </div>
        </div>
      </section>

      {/* Programmatic API */}
      <section className="max-w-4xl mx-auto px-6 py-12 border-t border-gray-800">
        <SectionHeading badge={t("apiBadge")} title={t("apiTitle")} description={t("apiDesc")} />
        <CodeBlock code={API_EXAMPLE} lang="ts" filename="example.ts" />
      </section>

      {/* CTA */}
      <section className="max-w-4xl mx-auto px-6 py-16 border-t border-gray-800">
        <div className="bg-gradient-to-br from-red-500/10 to-orange-500/10 border border-red-500/20 rounded-2xl p-8 md:p-12 text-center">
          <h2 className="text-2xl md:text-3xl font-bold mb-4">{t("ctaTitle")}</h2>
          <p className="text-gray-400 max-w-lg mx-auto mb-8">{t("ctaDesc")}</p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <div className="px-6 py-3 bg-gray-900 border border-gray-700 rounded-lg font-mono text-sm text-green-400">
              npm install -g @vexlit/cli
            </div>
            <Link href="/login" className="px-6 py-3 bg-red-600 rounded-lg font-medium text-sm hover:bg-red-700 transition-colors">
              {t("tryDashboard")}
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-800 py-8">
        <div className="max-w-7xl mx-auto px-6 flex flex-col sm:flex-row justify-between items-center gap-4">
          <span className="text-gray-600 text-sm">{tLanding("footer")}</span>
          <div className="flex gap-6">
            <a href="https://github.com/vexlit/vexlit" target="_blank" rel="noopener noreferrer" className="text-gray-600 hover:text-gray-400 text-sm transition-colors">
              GitHub
            </a>
            <Link href="/" className="text-gray-600 hover:text-gray-400 text-sm transition-colors">
              {tCommon("home")}
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
