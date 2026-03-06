"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { createSupabaseBrowser } from "@/lib/supabase-browser";
import { FadeIn, ScrollReveal, StaggerContainer, StaggerItem } from "./motion-wrapper";
import { LiveDemo } from "./live-demo";
import { RepoScanInput } from "./repo-scan-input";
import {
  BeforeAfterDemo,
  HowItWorks,
  SupportedLanguages,
  ComparisonTable,
  UsageMetrics,
  ScanOutputPreview,
} from "./landing-sections";

interface Rule {
  id: string;
  name: string;
  severity: string;
}

interface Feature {
  title: string;
  description: string;
  icon: string;
}

const ICONS: Record<string, React.ReactNode> = {
  tree: (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6z" />
    </svg>
  ),
  shield: (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
  ),
  github: (
    <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
      <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
    </svg>
  ),
  ai: (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456z" />
    </svg>
  ),
  chart: (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
    </svg>
  ),
  open: (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
    </svg>
  ),
};

export function LandingClient({
  rules,
  features,
}: {
  rules: Rule[];
  features: Feature[];
}) {
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    const supabase = createSupabaseBrowser();
    supabase.auth.getSession().then(({ data: { session } }) => {
      setIsLoggedIn(!!session);
    });
  }, []);

  const ctaHref = isLoggedIn ? "/dashboard" : "/login";

  return (
    <>
      {/* Hero */}
      <section className="max-w-4xl mx-auto px-6 pt-32 pb-16 text-center">
        <FadeIn>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-sm mb-6">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            263 security rules &middot; 3 languages
          </div>
        </FadeIn>
        <FadeIn delay={0.1}>
          <h1 className="text-5xl md:text-7xl font-bold leading-tight tracking-tight">
            Find Critical Security
            <br />
            <span className="bg-gradient-to-r from-red-500 to-orange-500 bg-clip-text text-transparent">
              Vulnerabilities in Seconds
            </span>
          </h1>
        </FadeIn>
        <FadeIn delay={0.2}>
          <p className="mt-6 text-lg md:text-xl text-gray-400 max-w-2xl mx-auto leading-relaxed">
            Scan your code for security issues with static analysis
            and AI-powered explanations developers can actually understand.
          </p>
        </FadeIn>
        <FadeIn delay={0.3}>
          <div className="mt-8 flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              href={ctaHref}
              className="px-8 py-3 bg-red-600 rounded-lg font-medium hover:bg-red-700 transition-all hover:shadow-lg hover:shadow-red-600/20"
            >
              {isLoggedIn ? "Go to Dashboard" : "Start Scanning Free"}
            </Link>
            <a
              href="https://github.com/vexlit/vexlit"
              target="_blank"
              rel="noopener noreferrer"
              className="px-8 py-3 border border-gray-700 rounded-lg font-medium hover:border-gray-500 transition-colors flex items-center justify-center gap-2"
            >
              {ICONS.github && <span className="w-5 h-5">{ICONS.github}</span>}
              View on GitHub
            </a>
          </div>
        </FadeIn>
        <FadeIn delay={0.4}>
          <div className="mt-10 pt-8 border-t border-gray-800/50">
            <p className="text-gray-500 text-sm mb-3">
              Scan any public GitHub repository — no sign-in required
            </p>
            <RepoScanInput />
          </div>
        </FadeIn>
      </section>

      {/* Live Demo */}
      <section className="max-w-4xl mx-auto px-6 pb-20">
        <ScrollReveal>
          <LiveDemo />
        </ScrollReveal>
      </section>

      {/* Before/After Demo */}
      <BeforeAfterDemo />

      {/* Scan Output Preview */}
      <ScanOutputPreview />

      {/* How It Works */}
      <HowItWorks />

      {/* Usage Metrics */}
      <UsageMetrics />

      {/* Features */}
      <section className="max-w-7xl mx-auto px-6 py-20">
        <ScrollReveal>
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-4">
            Why VEXLIT?
          </h2>
          <p className="text-gray-400 text-center max-w-2xl mx-auto mb-12">
            Enterprise-grade security scanning with the simplicity of a single command.
          </p>
        </ScrollReveal>

        <StaggerContainer className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((f) => (
            <StaggerItem key={f.title}>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 hover:border-gray-700 transition-all group h-full">
                <div className="w-10 h-10 rounded-lg bg-red-500/10 text-red-400 flex items-center justify-center mb-4 group-hover:bg-red-500/20 transition-colors">
                  {ICONS[f.icon]}
                </div>
                <h3 className="text-white font-semibold text-lg mb-2">
                  {f.title}
                </h3>
                <p className="text-gray-400 text-sm leading-relaxed">
                  {f.description}
                </p>
              </div>
            </StaggerItem>
          ))}
        </StaggerContainer>
      </section>

      {/* Rules preview */}
      <section className="max-w-4xl mx-auto px-6 py-16 border-t border-gray-800">
        <ScrollReveal>
          <h2 className="text-3xl font-bold text-center mb-3">
            Security Rules
          </h2>
          <p className="text-gray-400 text-center mb-8">
            Comprehensive coverage across injection, secrets, crypto, and more.
          </p>
        </ScrollReveal>

        <StaggerContainer className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
          {rules.map((rule) => (
            <StaggerItem key={rule.id}>
              <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 flex items-center gap-3 hover:border-gray-700 transition-colors">
                <span
                  className={`w-2 h-2 rounded-full flex-shrink-0 ${
                    rule.severity === "critical" ? "bg-red-500" : "bg-yellow-500"
                  }`}
                />
                <div className="min-w-0">
                  <p className="text-white text-sm truncate">{rule.name}</p>
                  <p className="text-gray-600 text-xs">{rule.id}</p>
                </div>
              </div>
            </StaggerItem>
          ))}
        </StaggerContainer>
        <ScrollReveal>
          <p className="text-center text-gray-500 text-sm mt-4">
            + 251 more rules including 200 secret patterns
          </p>
        </ScrollReveal>
      </section>

      {/* Supported Languages */}
      <SupportedLanguages />

      {/* Comparison Table */}
      <ComparisonTable />

      {/* CTA */}
      <section className="max-w-4xl mx-auto px-6 py-20">
        <ScrollReveal>
          <div className="bg-gradient-to-br from-red-500/10 to-orange-500/10 border border-red-500/20 rounded-2xl p-8 md:p-12 text-center">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Secure your code today
            </h2>
            <p className="text-gray-400 max-w-lg mx-auto mb-8">
              Connect your GitHub repository and get a comprehensive security scan in seconds. Free to use.
            </p>
            <Link
              href={ctaHref}
              className="inline-block px-8 py-3 bg-red-600 rounded-lg font-medium hover:bg-red-700 transition-all hover:shadow-lg hover:shadow-red-600/20"
            >
              {isLoggedIn ? "Go to Dashboard" : "Get Started Free"}
            </Link>
          </div>
        </ScrollReveal>
      </section>
    </>
  );
}
