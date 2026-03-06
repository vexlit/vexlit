import { Link } from "@/i18n/navigation";
import { LandingClient } from "@/components/landing/landing-client";
import { LandingNav } from "@/components/landing/landing-nav";
import { getTranslations } from "next-intl/server";

const RULES_PREVIEW = [
  { id: "VEXLIT-001", name: "Hardcoded Secrets", severity: "critical" },
  { id: "VEXLIT-002", name: "SQL Injection", severity: "critical" },
  { id: "VEXLIT-003", name: "XSS", severity: "critical" },
  { id: "VEXLIT-010", name: "Prototype Pollution", severity: "critical" },
  { id: "VEXLIT-011", name: "NoSQL Injection", severity: "critical" },
  { id: "VEXLIT-021", name: "Path Traversal", severity: "critical" },
  { id: "VEXLIT-022", name: "Command Injection", severity: "critical" },
  { id: "VEXLIT-007", name: "JWT Hardcoded Secret", severity: "critical" },
  { id: "VEXLIT-012", name: "SSRF", severity: "warning" },
  { id: "VEXLIT-018", name: "Timing Attack", severity: "warning" },
  { id: "VEXLIT-020", name: "Unsafe Deserialization", severity: "critical" },
  { id: "VEXLIT-023", name: "Eval Injection", severity: "critical" },
];

export default async function HomePage() {
  const t = await getTranslations("features");
  const tLanding = await getTranslations("landing");
  const tNav = await getTranslations("nav");

  const FEATURES = [
    { title: t("astAnalysis"), description: t("astAnalysisDesc"), icon: "tree" },
    { title: t("sastRules"), description: t("sastRulesDesc"), icon: "shield" },
    { title: t("githubIntegration"), description: t("githubIntegrationDesc"), icon: "github" },
    { title: t("aiVerification"), description: t("aiVerificationDesc"), icon: "ai" },
    { title: t("scanHistory"), description: t("scanHistoryDesc"), icon: "chart" },
    { title: t("freeOpenSource"), description: t("freeOpenSourceDesc"), icon: "open" },
  ];

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      <LandingNav />

      <LandingClient
        rules={RULES_PREVIEW}
        features={FEATURES}
      />

      {/* Footer */}
      <footer className="border-t border-gray-800 py-8">
        <div className="max-w-7xl mx-auto px-6 flex flex-col sm:flex-row justify-between items-center gap-4">
          <span className="text-gray-600 text-sm">
            {tLanding("footer")}
          </span>
          <div className="flex gap-6">
            <a
              href="https://github.com/vexlit/vexlit"
              target="_blank"
              rel="noopener noreferrer"
              className="text-gray-600 hover:text-gray-400 text-sm transition-colors"
            >
              GitHub
            </a>
            <Link
              href="/login"
              className="text-gray-600 hover:text-gray-400 text-sm transition-colors"
            >
              {tNav("dashboard")}
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
