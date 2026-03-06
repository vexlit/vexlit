"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { ScrollReveal, StaggerContainer, StaggerItem } from "./motion-wrapper";

/* ─────────────────────────── Before / After Demo ─────────────────────────── */

const DEMO_TABS = [
  {
    label: "SQL Injection",
    vulnerable: `// Express API handler
app.get("/users", (req, res) => {
  db.query(\`SELECT * FROM users
    WHERE name = '\${req.query.name}'\`);
});`,
    fixed: `// Express API handler
app.get("/users", (req, res) => {
  db.query("SELECT * FROM users WHERE name = ?",
    [req.query.name]);
});`,
    finding: {
      rule: "SQL Injection",
      id: "VEXLIT-002",
      severity: "critical",
      line: 3,
      message: "Template literal in SQL query — possible SQL injection. Use parameterized queries.",
      cwe: "CWE-89",
    },
  },
  {
    label: "Hardcoded Secret",
    vulnerable: `// Auth configuration
const config = {
  jwtSecret: "sk_live_a1b2c3d4e5f6",
  apiKey: "AKIAIOSFODNN7EXAMPLE",
  dbPassword: "admin123!",
};`,
    fixed: `// Auth configuration
const config = {
  jwtSecret: process.env.JWT_SECRET,
  apiKey: process.env.API_KEY,
  dbPassword: process.env.DB_PASSWORD,
};`,
    finding: {
      rule: "Hardcoded Secret",
      id: "VEXLIT-001",
      severity: "critical",
      line: 3,
      message: "Potential secret key found in source code. Use environment variables.",
      cwe: "CWE-798",
    },
  },
  {
    label: "XSS",
    vulnerable: `// React component
function Comment({ text }) {
  return (
    <div
      dangerouslySetInnerHTML={{
        __html: text
      }}
    />
  );
}`,
    fixed: `// React component
function Comment({ text }) {
  return (
    <div>
      {DOMPurify.sanitize(text)}
    </div>
  );
}`,
    finding: {
      rule: "Cross-Site Scripting",
      id: "VEXLIT-003",
      severity: "warning",
      line: 5,
      message: "dangerouslySetInnerHTML — potential XSS vector. Sanitize with DOMPurify.",
      cwe: "CWE-79",
    },
  },
];

export function BeforeAfterDemo() {
  const [activeTab, setActiveTab] = useState(0);
  const demo = DEMO_TABS[activeTab];
  const t = useTranslations("sections");

  return (
    <section id="demo" className="max-w-6xl mx-auto px-6 py-20 border-t border-gray-800 scroll-mt-20">
      <ScrollReveal>
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-3">
          {t("beforeAfterTitle")}
        </h2>
        <p className="text-gray-400 text-center max-w-2xl mx-auto mb-10">
          {t("beforeAfterDesc")}
        </p>
      </ScrollReveal>

      <ScrollReveal>
        {/* Tabs */}
        <div className="flex gap-2 justify-center mb-6">
          {DEMO_TABS.map((tab, i) => (
            <button
              key={tab.label}
              onClick={() => setActiveTab(i)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                i === activeTab
                  ? "bg-red-600 text-white"
                  : "bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Code panels */}
        <div className="grid md:grid-cols-2 gap-4">
          {/* Vulnerable */}
          <div className="bg-gray-900 border border-red-500/30 rounded-xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-2 bg-red-500/10 border-b border-red-500/20">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              <span className="text-red-400 text-xs font-medium">Vulnerable</span>
            </div>
            <pre className="p-4 text-sm text-gray-300 overflow-x-auto leading-relaxed">
              <code>{demo.vulnerable}</code>
            </pre>
          </div>

          {/* Fixed */}
          <div className="bg-gray-900 border border-green-500/30 rounded-xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-2 bg-green-500/10 border-b border-green-500/20">
              <span className="w-2 h-2 rounded-full bg-green-500" />
              <span className="text-green-400 text-xs font-medium">Fixed</span>
            </div>
            <pre className="p-4 text-sm text-gray-300 overflow-x-auto leading-relaxed">
              <code>{demo.fixed}</code>
            </pre>
          </div>
        </div>

        {/* Finding card */}
        <div className="mt-4 bg-gray-900 border border-gray-800 rounded-xl p-4">
          <div className="flex items-start gap-3">
            <span className={`mt-0.5 w-2.5 h-2.5 rounded-full flex-shrink-0 ${demo.finding.severity === "critical" ? "bg-red-500" : demo.finding.severity === "warning" ? "bg-yellow-500" : "bg-blue-500"}`} />
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-white font-medium text-sm">{demo.finding.rule}</span>
                <span className="text-gray-600 text-xs font-mono">{demo.finding.id}</span>
                <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${demo.finding.severity === "critical" ? "bg-red-500/10 text-red-400" : demo.finding.severity === "warning" ? "bg-yellow-500/10 text-yellow-400" : "bg-blue-500/10 text-blue-400"}`}>
                  {demo.finding.severity}
                </span>
                <span className="text-gray-600 text-xs">{demo.finding.cwe}</span>
              </div>
              <p className="text-gray-400 text-sm mt-1">{demo.finding.message}</p>
              <p className="text-gray-600 text-xs mt-1">Line {demo.finding.line}</p>
            </div>
          </div>
        </div>
      </ScrollReveal>
    </section>
  );
}

/* ─────────────────────────── How It Works ─────────────────────────── */

const STEP_ICONS = [
  <svg key="1" className="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m9.86-2.07a4.5 4.5 0 00-1.242-7.244l-4.5-4.5a4.5 4.5 0 00-6.364 6.364L4.343 8.82" /></svg>,
  <svg key="2" className="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" /></svg>,
  <svg key="3" className="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" /></svg>,
];

const STEP_KEYS = [
  { step: "01", titleKey: "step1Title" as const, descKey: "step1Desc" as const },
  { step: "02", titleKey: "step2Title" as const, descKey: "step2Desc" as const },
  { step: "03", titleKey: "step3Title" as const, descKey: "step3Desc" as const },
];

export function HowItWorks() {
  const t = useTranslations("sections");
  return (
    <section id="how-it-works" className="max-w-5xl mx-auto px-6 py-20 border-t border-gray-800 scroll-mt-20">
      <ScrollReveal>
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-3">
          {t("howItWorksTitle")}
        </h2>
        <p className="text-gray-400 text-center max-w-2xl mx-auto mb-12">
          {t("howItWorksDesc")}
        </p>
      </ScrollReveal>

      <StaggerContainer className="grid md:grid-cols-3 gap-8">
        {STEP_KEYS.map((s, i) => (
          <StaggerItem key={s.step}>
            <div className="relative bg-gray-900 border border-gray-800 rounded-xl p-6 hover:border-gray-700 transition-all group h-full">
              <span className="absolute -top-3 -left-2 text-5xl font-black text-gray-800/50 select-none">
                {s.step}
              </span>
              <div className="w-12 h-12 rounded-lg bg-red-500/10 text-red-400 flex items-center justify-center mb-4 group-hover:bg-red-500/20 transition-colors">
                {STEP_ICONS[i]}
              </div>
              <h3 className="text-white font-semibold text-lg mb-2">{t(s.titleKey)}</h3>
              <p className="text-gray-400 text-sm leading-relaxed">{t(s.descKey)}</p>
            </div>
          </StaggerItem>
        ))}
      </StaggerContainer>
    </section>
  );
}

/* ─────────────────────────── Supported Languages ─────────────────────────── */

const LANGUAGES = [
  {
    name: "JavaScript",
    icon: "JS",
    color: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
    status: "supported" as const,
  },
  {
    name: "TypeScript",
    icon: "TS",
    color: "text-blue-400 bg-blue-400/10 border-blue-400/20",
    status: "supported" as const,
  },
  {
    name: "Python",
    icon: "PY",
    color: "text-green-400 bg-green-400/10 border-green-400/20",
    status: "supported" as const,
  },
  {
    name: "Go",
    icon: "GO",
    color: "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
    status: "coming" as const,
  },
  {
    name: "Java",
    icon: "JV",
    color: "text-orange-400 bg-orange-400/10 border-orange-400/20",
    status: "coming" as const,
  },
  {
    name: "Rust",
    icon: "RS",
    color: "text-amber-400 bg-amber-400/10 border-amber-400/20",
    status: "coming" as const,
  },
];

export function SupportedLanguages() {
  const t = useTranslations("sections");
  return (
    <section id="languages" className="max-w-4xl mx-auto px-6 py-20 border-t border-gray-800 scroll-mt-20">
      <ScrollReveal>
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-3">
          {t("languagesTitle")}
        </h2>
        <p className="text-gray-400 text-center max-w-2xl mx-auto mb-10">
          {t("languagesDesc")}
        </p>
      </ScrollReveal>

      <StaggerContainer className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-4">
        {LANGUAGES.map((lang) => (
          <StaggerItem key={lang.name}>
            <div className={`relative flex flex-col items-center gap-2 p-4 rounded-xl border transition-all hover:scale-105 ${
              lang.status === "supported"
                ? "bg-gray-900 border-gray-800 hover:border-gray-700"
                : "bg-gray-900/50 border-gray-800/50"
            }`}>
              {lang.status === "coming" && (
                <span className="absolute -top-2 right-2 px-1.5 py-0.5 bg-gray-800 text-gray-500 text-[10px] rounded font-medium">
                  Soon
                </span>
              )}
              <span className={`w-12 h-12 rounded-lg border flex items-center justify-center text-sm font-bold ${lang.color}`}>
                {lang.icon}
              </span>
              <span className={`text-sm font-medium ${
                lang.status === "supported" ? "text-white" : "text-gray-500"
              }`}>
                {lang.name}
              </span>
            </div>
          </StaggerItem>
        ))}
      </StaggerContainer>
    </section>
  );
}

/* ─────────────────────────── Comparison Table ─────────────────────────── */

const COMPARISON_KEYS = [
  { featureKey: "compFeatureSast" as const, vexlit: true, othersKey: "compOtherPaid" as const },
  { featureKey: "compFeatureAiFix" as const, vexlit: true, othersKey: "compOtherLimited" as const },
  { featureKey: "compFeaturePrCheck" as const, vexlit: true, othersKey: "compOtherPaid" as const },
  { featureKey: "compFeatureScheduled" as const, vexlit: true, othersKey: "compOtherPaid" as const },
  { featureKey: "compFeatureAlerts" as const, vexlit: true, othersKey: "compOtherPartial" as const },
  { featureKey: "compFeatureOpenSource" as const, vexlit: true, othersKey: "compOtherClosed" as const },
  { featureKey: "compFeatureSarif" as const, vexlit: true, othersKey: "compOtherPaid" as const },
  { featureKey: "compFeatureNoCreditCard" as const, vexlit: true, othersKey: "compOtherVaries" as const },
  { featureKey: "compFeatureHistory" as const, vexlit: true, othersKey: "compOtherPaid" as const },
];

function CheckIcon() {
  return (
    <svg className="w-5 h-5 text-green-400 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
    </svg>
  );
}

function CrossIcon() {
  return (
    <svg className="w-5 h-5 text-gray-600 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}

export function ComparisonTable() {
  const t = useTranslations("sections");
  return (
    <section id="comparison" className="max-w-4xl mx-auto px-6 py-20 border-t border-gray-800 scroll-mt-20">
      <ScrollReveal>
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-3">
          {t("comparisonTitle")}
        </h2>
        <p className="text-gray-400 text-center max-w-2xl mx-auto mb-10">
          {t("comparisonDesc")}
        </p>
      </ScrollReveal>

      <ScrollReveal>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="text-left py-3 px-4 text-gray-400 text-sm font-medium">{t("compHeaderFeature")}</th>
                <th className="py-3 px-4 text-center">
                  <span className="text-red-400 font-bold text-sm">VEXLIT</span>
                </th>
                <th className="py-3 px-4 text-center">
                  <span className="text-gray-400 text-sm">{t("compHeaderOthers")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {COMPARISON_KEYS.map((row) => (
                <tr key={row.featureKey} className="border-b border-gray-800/50 hover:bg-gray-900/50 transition-colors">
                  <td className="py-3 px-4 text-white text-sm">{t(row.featureKey)}</td>
                  <td className="py-3 px-4">{row.vexlit ? <CheckIcon /> : <CrossIcon />}</td>
                  <td className="py-3 px-4 text-center text-gray-500 text-sm">{t(row.othersKey)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </ScrollReveal>
    </section>
  );
}

/* ─────────────────────────── Usage Metrics ─────────────────────────── */

export function UsageMetrics() {
  const t = useTranslations("sections");
  return (
    <section className="border-t border-b border-gray-800 py-16 bg-gradient-to-b from-gray-950 to-gray-900/50">
      <ScrollReveal>
        <div className="max-w-5xl mx-auto px-6">
          <h2 className="text-2xl md:text-3xl font-bold text-center mb-10">
            {t("metricsTitle")}
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-8 text-center">
            <div>
              <p className="text-3xl md:text-4xl font-bold text-red-400">85+</p>
              <p className="text-gray-500 text-sm mt-1">{t("metricSastRules")}</p>
            </div>
            <div>
              <p className="text-3xl md:text-4xl font-bold text-red-400">200+</p>
              <p className="text-gray-500 text-sm mt-1">{t("metricSecretPatterns")}</p>
            </div>
            <div>
              <p className="text-3xl md:text-4xl font-bold text-red-400">10+</p>
              <p className="text-gray-500 text-sm mt-1">{t("metricOwaspCategories")}</p>
            </div>
            <div>
              <p className="text-3xl md:text-4xl font-bold text-red-400">&lt;10s</p>
              <p className="text-gray-500 text-sm mt-1">{t("metricAvgScanTime")}</p>
            </div>
            <div>
              <p className="text-3xl md:text-4xl font-bold text-red-400">100%</p>
              <p className="text-gray-500 text-sm mt-1">{t("metricFree")}</p>
            </div>
          </div>
        </div>
      </ScrollReveal>
    </section>
  );
}

/* ─────────────────────────── Scan Output Preview ─────────────────────────── */

const PREVIEW_FINDINGS = [
  {
    severity: "critical" as const,
    rule: "SQL Injection",
    id: "VEXLIT-002",
    file: "api/users.js",
    line: 42,
    message: "User input directly interpolated into SQL query",
    cwe: "CWE-89",
  },
  {
    severity: "critical" as const,
    rule: "Hardcoded Secret",
    id: "VEXLIT-001",
    file: "config/auth.ts",
    line: 12,
    message: "API key found in source code",
    cwe: "CWE-798",
  },
  {
    severity: "warning" as const,
    rule: "SSRF",
    id: "VEXLIT-012",
    file: "lib/fetch.ts",
    line: 28,
    message: "User-controlled URL passed to fetch without validation",
    cwe: "CWE-918",
  },
  {
    severity: "info" as const,
    rule: "Console Log",
    id: "VEXLIT-045",
    file: "utils/debug.js",
    line: 5,
    message: "Console statement left in production code",
    cwe: "CWE-215",
  },
];

const SEVERITY_STYLES = {
  critical: "bg-red-500",
  warning: "bg-yellow-500",
  info: "bg-blue-500",
};

export function ScanOutputPreview() {
  const t = useTranslations("sections");
  return (
    <section className="max-w-4xl mx-auto px-6 py-20 border-t border-gray-800">
      <ScrollReveal>
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-3">
          {t("scanOutputTitle")}
        </h2>
        <p className="text-gray-400 text-center max-w-2xl mx-auto mb-10">
          {t("scanOutputDesc")}
        </p>
      </ScrollReveal>

      <ScrollReveal>
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800 bg-gray-900/80">
            <div className="flex items-center gap-3">
              <span className="w-2.5 h-2.5 rounded-full bg-green-500" />
              <span className="text-white text-sm font-medium">Scan completed</span>
              <span className="text-gray-600 text-xs">2.4s</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 bg-red-500/10 text-red-400 rounded text-xs font-medium">2 critical</span>
              <span className="px-2 py-0.5 bg-yellow-500/10 text-yellow-400 rounded text-xs font-medium">1 warning</span>
              <span className="px-2 py-0.5 bg-blue-500/10 text-blue-400 rounded text-xs font-medium">1 info</span>
            </div>
          </div>

          {/* Findings */}
          <div className="divide-y divide-gray-800/50">
            {PREVIEW_FINDINGS.map((f) => (
              <div key={f.id + f.line} className="flex items-start gap-3 px-4 py-3 hover:bg-gray-800/30 transition-colors">
                <span className={`mt-1.5 w-2 h-2 rounded-full flex-shrink-0 ${SEVERITY_STYLES[f.severity]}`} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-white text-sm font-medium">{f.rule}</span>
                    <span className="text-gray-600 text-xs font-mono">{f.id}</span>
                    <span className="text-gray-600 text-xs">{f.cwe}</span>
                  </div>
                  <p className="text-gray-400 text-sm mt-0.5">{f.message}</p>
                  <p className="text-gray-600 text-xs mt-0.5 font-mono">{f.file}:{f.line}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </ScrollReveal>
    </section>
  );
}
