import type { ReactNode } from "react";
import { Link } from "@/i18n/navigation";
import { LandingNav } from "@/components/landing/landing-nav";
import { getTranslations } from "next-intl/server";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "VSCode Extension — VEXLIT",
  description: "Real-time security scanning inside your editor. Inline vulnerability detection, hover fix suggestions, and AI-powered remediation.",
};

const FEATURES = [
  { key: "feature1", icon: "underline" },
  { key: "feature2", icon: "hover" },
  { key: "feature3", icon: "ai" },
  { key: "feature4", icon: "rules" },
  { key: "feature5", icon: "secret" },
  { key: "feature6", icon: "zero" },
] as const;

const FEATURE_ICONS: Record<string, ReactNode> = {
  underline: (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
    </svg>
  ),
  hover: (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15.042 21.672L13.684 16.6m0 0l-2.51 2.225.569-9.47 5.227 7.917-3.286-.672zM12 2.25V4.5m5.834.166l-1.591 1.591M20.25 10.5H18M7.757 14.743l-1.59 1.59M6 10.5H3.75m4.007-4.243l-1.59-1.59" />
    </svg>
  ),
  ai: (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456z" />
    </svg>
  ),
  rules: (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
  ),
  secret: (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
    </svg>
  ),
  zero: (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
    </svg>
  ),
};

export default async function VSCodePage() {
  const t = await getTranslations("vscode");
  const tCommon = await getTranslations("common");
  const tLanding = await getTranslations("landing");

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      <LandingNav />

      {/* Hero */}
      <section className="max-w-4xl mx-auto px-6 pt-28 pb-12">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400 text-sm mb-6">
          <span className="w-2 h-2 rounded-full bg-purple-500 animate-pulse" />
          {t("badge")}
        </div>
        <h1 className="text-4xl md:text-5xl font-bold leading-tight tracking-tight mb-4">
          {t("heroTitle1")}{" "}
          <span className="bg-gradient-to-r from-purple-500 to-blue-500 bg-clip-text text-transparent">
            {t("heroTitle2")}
          </span>
        </h1>
        <p className="text-lg text-gray-400 max-w-2xl mb-8">{t("heroDescription")}</p>
        <div className="flex flex-wrap gap-3">
          <button
            disabled
            className="px-5 py-2.5 bg-purple-600 rounded-lg text-sm font-medium opacity-60 cursor-not-allowed"
          >
            {t("notifyMe")}
          </button>
          <Link
            href="/docs"
            className="px-5 py-2.5 border border-gray-700 rounded-lg text-sm font-medium hover:border-gray-500 transition-colors"
          >
            {t("viewCli")}
          </Link>
        </div>
      </section>

      {/* IDE Preview Mock */}
      <section className="max-w-4xl mx-auto px-6 py-8">
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          {/* Title bar */}
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-gray-800 bg-gray-900/80">
            <div className="flex gap-1.5">
              <span className="w-3 h-3 rounded-full bg-red-500/80" />
              <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
              <span className="w-3 h-3 rounded-full bg-green-500/80" />
            </div>
            <span className="text-gray-500 text-xs font-mono ml-3">auth.ts — VEXLIT</span>
          </div>
          {/* Code with inline warnings */}
          <div className="p-4 font-mono text-sm leading-relaxed">
            <div className="text-gray-500">1  <span className="text-purple-400">import</span> <span className="text-gray-300">express</span> <span className="text-purple-400">from</span> <span className="text-green-400">&quot;express&quot;</span>;</div>
            <div className="text-gray-500">2</div>
            <div className="text-gray-500 relative">
              3  <span className="text-purple-400">const</span> <span className="text-gray-300">API_KEY</span> = <span className="text-green-400 underline decoration-wavy decoration-red-500">&quot;sk-secret-12345&quot;</span>;
              <span className="absolute right-0 top-0 text-[10px] text-red-400 bg-red-500/10 px-2 py-0.5 rounded-l">VEXLIT-001 Hardcoded Secret</span>
            </div>
            <div className="text-gray-500">4</div>
            <div className="text-gray-500">5  app.<span className="text-yellow-300">get</span>(<span className="text-green-400">&quot;/user&quot;</span>, (<span className="text-orange-300">req</span>, <span className="text-orange-300">res</span>) =&gt; {"{"}</div>
            <div className="text-gray-500 relative">
              6    <span className="text-purple-400">const</span> q = <span className="text-gray-300 underline decoration-wavy decoration-red-500">`SELECT * FROM users WHERE id=${"{"}<span className="text-orange-300">req</span>.query.id{"}"}`</span>;
              <span className="absolute right-0 top-0 text-[10px] text-red-400 bg-red-500/10 px-2 py-0.5 rounded-l">VEXLIT-002 SQL Injection</span>
            </div>
            <div className="text-gray-500">7  {"}"});</div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="max-w-4xl mx-auto px-6 py-12 border-t border-gray-800">
        <div className="mb-8">
          <span className="inline-block px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400 text-xs font-medium mb-4">
            {t("featuresBadge")}
          </span>
          <h2 className="text-2xl md:text-3xl font-bold text-white mb-3">{t("featuresTitle")}</h2>
          <p className="text-gray-400 max-w-2xl">{t("featuresDesc")}</p>
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {FEATURES.map((f) => (
            <div key={f.key} className="bg-gray-900 border border-gray-800 rounded-xl p-5 hover:border-gray-700 transition-colors">
              <div className="w-10 h-10 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 mb-4">
                {FEATURE_ICONS[f.icon]}
              </div>
              <h3 className="text-white font-medium mb-2">{t(`${f.key}Title`)}</h3>
              <p className="text-gray-400 text-sm">{t(`${f.key}Desc`)}</p>
            </div>
          ))}
        </div>
      </section>

      {/* How it works */}
      <section className="max-w-4xl mx-auto px-6 py-12 border-t border-gray-800">
        <div className="mb-8">
          <span className="inline-block px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400 text-xs font-medium mb-4">
            {t("howBadge")}
          </span>
          <h2 className="text-2xl md:text-3xl font-bold text-white mb-3">{t("howTitle")}</h2>
          <p className="text-gray-400 max-w-2xl">{t("howDesc")}</p>
        </div>
        <div className="flex flex-col md:flex-row gap-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="flex-1 bg-gray-900 border border-gray-800 rounded-xl p-5">
              <div className="w-8 h-8 rounded-full bg-purple-600 text-white text-sm font-bold flex items-center justify-center mb-3">
                {i}
              </div>
              <p className="text-gray-300 text-sm">{t(`step${i}`)}</p>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="max-w-4xl mx-auto px-6 py-16 border-t border-gray-800">
        <div className="bg-gradient-to-br from-purple-500/10 to-blue-500/10 border border-purple-500/20 rounded-2xl p-8 md:p-12 text-center">
          <h2 className="text-2xl md:text-3xl font-bold mb-4">{t("ctaTitle")}</h2>
          <p className="text-gray-400 max-w-lg mx-auto mb-8">{t("ctaDesc")}</p>
          <div className="flex flex-col sm:flex-row gap-3 justify-center max-w-md mx-auto">
            <input
              type="email"
              placeholder={t("emailPlaceholder")}
              className="flex-1 px-4 py-3 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-purple-500"
              disabled
            />
            <button
              disabled
              className="px-6 py-3 bg-purple-600 rounded-lg font-medium text-sm opacity-60 cursor-not-allowed"
            >
              {t("subscribe")}
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-800 py-8">
        <div className="max-w-7xl mx-auto px-6 flex flex-col sm:flex-row justify-between items-center gap-4">
          <span className="text-gray-600 text-sm">{tLanding("footer")}</span>
          <div className="flex gap-6">
            <Link href="/docs" className="text-gray-600 hover:text-gray-400 text-sm transition-colors">
              CLI Docs
            </Link>
            <Link href="/" className="text-gray-600 hover:text-gray-400 text-sm transition-colors">
              {tCommon("home")}
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
