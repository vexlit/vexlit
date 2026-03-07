"use client";

import { useState, useEffect, useCallback } from "react";
import { useTranslations } from "next-intl";
import { ScrollReveal, StaggerContainer, StaggerItem } from "./motion-wrapper";
import { AnimatedCounter } from "./counter";

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

type Phase = "vulnerable" | "scanning" | "detected" | "fixed";
const PHASE_DURATION: Record<Phase, number> = {
  vulnerable: 2000,
  scanning: 1500,
  detected: 2500,
  fixed: 3000,
};
const PHASE_ORDER: Phase[] = ["vulnerable", "scanning", "detected", "fixed"];

export function BeforeAfterDemo() {
  const [activeTab, setActiveTab] = useState(0);
  const [phase, setPhase] = useState<Phase>("vulnerable");
  const [paused, setPaused] = useState(false);
  const demo = DEMO_TABS[activeTab];
  const t = useTranslations("sections");

  const advancePhase = useCallback(() => {
    setPhase((prev) => {
      const idx = PHASE_ORDER.indexOf(prev);
      if (idx < PHASE_ORDER.length - 1) return PHASE_ORDER[idx + 1];
      // End of cycle → next tab
      setActiveTab((tab) => (tab + 1) % DEMO_TABS.length);
      return "vulnerable";
    });
  }, []);

  useEffect(() => {
    if (paused) return;
    const timer = setTimeout(advancePhase, PHASE_DURATION[phase]);
    return () => clearTimeout(timer);
  }, [phase, paused, advancePhase]);

  // Reset phase when user clicks a tab
  const handleTabClick = (i: number) => {
    setActiveTab(i);
    setPhase("vulnerable");
  };

  const showCode = phase === "vulnerable" || phase === "scanning" ? demo.vulnerable : demo.fixed;
  const isScanning = phase === "scanning";
  const showFinding = phase === "detected" || phase === "fixed";
  const isFixed = phase === "fixed";

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
        {/* Tabs + pause button */}
        <div className="flex gap-2 justify-center mb-6 items-center">
          {DEMO_TABS.map((tab, i) => (
            <button
              key={tab.label}
              onClick={() => handleTabClick(i)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                i === activeTab
                  ? "bg-red-600 text-white"
                  : "bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700"
              }`}
            >
              {tab.label}
            </button>
          ))}
          <button
            onClick={() => setPaused(!paused)}
            className="ml-2 p-2 rounded-lg text-gray-500 hover:text-white hover:bg-gray-800 transition-colors"
            title={paused ? "Play" : "Pause"}
          >
            {paused ? (
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
            ) : (
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M6 4h4v16H6V4zm8 0h4v16h-4V4z"/></svg>
            )}
          </button>
        </div>

        {/* Phase indicator */}
        <div className="flex justify-center gap-1 mb-4">
          {PHASE_ORDER.map((p) => (
            <div
              key={p}
              className={`h-1 rounded-full transition-all duration-500 ${
                PHASE_ORDER.indexOf(p) <= PHASE_ORDER.indexOf(phase)
                  ? isFixed ? "bg-green-500 w-8" : "bg-red-500 w-8"
                  : "bg-gray-800 w-4"
              }`}
            />
          ))}
        </div>

        {/* Single code panel with animated state */}
        <div
          className={`bg-gray-900 border rounded-xl overflow-hidden transition-colors duration-500 ${
            isFixed ? "border-green-500/30" : "border-red-500/30"
          }`}
          onMouseEnter={() => setPaused(true)}
          onMouseLeave={() => setPaused(false)}
        >
          {/* Title bar */}
          <div className={`flex items-center justify-between px-4 py-2 border-b transition-colors duration-500 ${
            isFixed ? "bg-green-500/10 border-green-500/20" : "bg-red-500/10 border-red-500/20"
          }`}>
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full transition-colors duration-500 ${isFixed ? "bg-green-500" : "bg-red-500"}`} />
              <span className={`text-xs font-medium transition-colors duration-500 ${isFixed ? "text-green-400" : "text-red-400"}`}>
                {isFixed ? "✓ Fixed" : isScanning ? "Scanning..." : showFinding ? `${t("vulnFound")}` : t("before")}
              </span>
            </div>
            {isScanning && (
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
                <span className="text-gray-500 text-xs">VEXLIT</span>
              </div>
            )}
          </div>

          {/* Code with optional highlight */}
          <div className="relative">
            <pre className="p-4 text-sm text-gray-300 overflow-x-auto leading-relaxed transition-opacity duration-300">
              <code>{showCode}</code>
            </pre>
            {/* Scan line animation */}
            {isScanning && (
              <div className="absolute inset-0 pointer-events-none overflow-hidden">
                <div className="absolute left-0 right-0 h-6 bg-gradient-to-b from-red-500/10 to-transparent animate-[scanLine_1.5s_ease-in-out_infinite]" />
              </div>
            )}
          </div>
        </div>

        {/* Finding card — slides in when detected */}
        <div className={`mt-4 transition-all duration-500 ${showFinding ? "opacity-100 translate-y-0" : "opacity-0 -translate-y-2 pointer-events-none h-0 mt-0 overflow-hidden"}`}>
          <div className={`bg-gray-900 border rounded-xl p-4 transition-colors duration-500 ${isFixed ? "border-green-500/30" : "border-gray-800"}`}>
            <div className="flex items-start gap-3">
              <span className={`mt-0.5 w-2.5 h-2.5 rounded-full flex-shrink-0 ${demo.finding.severity === "critical" ? "bg-red-500" : demo.finding.severity === "warning" ? "bg-yellow-500" : "bg-blue-500"}`} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-white font-medium text-sm">{demo.finding.rule}</span>
                  <span className="text-gray-600 text-xs font-mono">{demo.finding.id}</span>
                  <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${demo.finding.severity === "critical" ? "bg-red-500/10 text-red-400" : demo.finding.severity === "warning" ? "bg-yellow-500/10 text-yellow-400" : "bg-blue-500/10 text-blue-400"}`}>
                    {demo.finding.severity}
                  </span>
                  <span className="text-gray-600 text-xs">{demo.finding.cwe}</span>
                </div>
                <p className="text-gray-400 text-sm mt-1">{demo.finding.message}</p>
                {isFixed && (
                  <p className="text-green-400 text-sm mt-2 flex items-center gap-1.5">
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    AI Fix applied
                  </p>
                )}
              </div>
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

/* ─────────────────────────── Accuracy Benchmark ─────────────────────────── */

const BENCHMARK_RESULTS = [
  { name: "SQL Injection", f1: 96.2, color: "text-green-400" },
  { name: "XSS", f1: 98.5, color: "text-green-400" },
  { name: "Command Injection", f1: 97.8, color: "text-green-400" },
  { name: "Hardcoded Secrets", f1: 99.1, color: "text-green-400" },
  { name: "Eval Injection", f1: 98.0, color: "text-green-400" },
  { name: "SSRF", f1: 95.6, color: "text-green-400" },
  { name: "Path Traversal", f1: 97.3, color: "text-green-400" },
  { name: "Prototype Pollution", f1: 96.8, color: "text-green-400" },
  { name: "Insecure Crypto", f1: 99.4, color: "text-green-400" },
  { name: "NoSQL Injection", f1: 95.2, color: "text-green-400" },
  { name: "Insecure Cookie", f1: 98.7, color: "text-green-400" },
  { name: "Open Redirect", f1: 96.5, color: "text-green-400" },
];

export function AccuracyBenchmark() {
  const t = useTranslations("sections");
  return (
    <section id="accuracy" className="max-w-6xl mx-auto px-6 py-20 border-t border-gray-800 scroll-mt-20">
      <ScrollReveal>
        <div className="flex justify-center mb-4">
          <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-gray-800 border border-gray-700 text-gray-300 text-sm">
            <span className="w-2 h-2 rounded-full bg-green-500" />
            {t("benchmarkBadge")}
          </span>
        </div>
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-3">
          {t("benchmarkTitle")}
        </h2>
        <p className="text-gray-400 text-center max-w-2xl mx-auto mb-12">
          {t("benchmarkDesc")}
        </p>
      </ScrollReveal>

      {/* Main metrics — 3 key stats */}
      <ScrollReveal>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 sm:gap-6 mb-12">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 sm:p-6 text-center hover:border-gray-700 transition-colors">
            <AnimatedCounter end={97.4} suffix="%" decimals={1} label={t("benchmarkRecall")} />
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 sm:p-6 text-center hover:border-gray-700 transition-colors">
            <p className="text-3xl sm:text-4xl md:text-5xl font-bold text-white">&lt;1%</p>
            <p className="text-gray-400 text-sm mt-2">{t("benchmarkFPR")}</p>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 sm:p-6 text-center hover:border-gray-700 transition-colors">
            <AnimatedCounter end={11100} suffix="+" label={t("benchmarkSamples")} />
          </div>
        </div>
      </ScrollReveal>

      {/* What this means */}
      <ScrollReveal>
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 md:p-8 mb-12">
          <h3 className="text-white font-semibold mb-3">{t("benchmarkWhatMeans")}</h3>
          <div className="grid md:grid-cols-2 gap-4 text-sm">
            <div className="flex items-start gap-3">
              <span className="w-5 h-5 rounded-full bg-green-500/10 text-green-400 flex items-center justify-center flex-shrink-0 mt-0.5 text-xs font-bold">1</span>
              <p className="text-gray-400">{t("benchmarkMeaning1")}</p>
            </div>
            <div className="flex items-start gap-3">
              <span className="w-5 h-5 rounded-full bg-green-500/10 text-green-400 flex items-center justify-center flex-shrink-0 mt-0.5 text-xs font-bold">2</span>
              <p className="text-gray-400">{t("benchmarkMeaning2")}</p>
            </div>
          </div>
        </div>
      </ScrollReveal>

      {/* Category breakdown with actual F1 scores */}
      <ScrollReveal>
        <h3 className="text-lg font-semibold text-center mb-6">{t("benchmarkCategories")}</h3>
        <StaggerContainer className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
          {BENCHMARK_RESULTS.map((cat) => (
            <StaggerItem key={cat.name}>
              <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 flex items-center gap-3 hover:border-gray-700 transition-colors">
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${cat.f1 === 100 ? "bg-green-500" : "bg-yellow-500"}`} />
                <div className="min-w-0 flex-1">
                  <p className="text-white text-sm truncate">{cat.name}</p>
                  <p className={`text-xs font-mono ${cat.color}`}>{cat.f1}% F1</p>
                </div>
              </div>
            </StaggerItem>
          ))}
        </StaggerContainer>
        <p className="text-center text-gray-500 text-xs mt-6 max-w-2xl mx-auto">
          {t("benchmarkFootnote")}
        </p>
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
