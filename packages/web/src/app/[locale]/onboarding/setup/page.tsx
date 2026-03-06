"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";

const FEATURE_KEYS = [
  { key: "feature_pr_check", labelKey: "prCheck" as const, descKey: "prCheckDesc" as const },
  { key: "feature_scheduled_scan", labelKey: "scheduledScan" as const, descKey: "scheduledScanDesc" as const },
  { key: "feature_security_alerts", labelKey: "securityAlerts" as const, descKey: "securityAlertsDesc" as const },
  { key: "feature_code_analysis", labelKey: "codeAnalysis" as const, descKey: "codeAnalysisDesc" as const },
];

export default function OnboardingSetupPage() {
  const router = useRouter();
  const t = useTranslations("onboarding");
  const [repoScope, setRepoScope] = useState<"public_only" | "all">("public_only");
  const [features, setFeatures] = useState<Record<string, boolean>>({
    feature_pr_check: true,
    feature_scheduled_scan: true,
    feature_security_alerts: true,
    feature_code_analysis: true,
  });
  const [loading, setLoading] = useState(false);

  const toggleFeature = (key: string) => {
    setFeatures((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleComplete = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/profile", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_scope: repoScope, ...features }),
      });
      if (res.ok) {
        router.push("/dashboard");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center px-4">
      <div className="w-full max-w-2xl">
        <div className="text-center mb-8">
          <h1 className="text-2xl font-bold text-white">{t("setupTitle")}</h1>
          <p className="text-gray-400 text-sm mt-2">{t("setupSubtitle")}</p>
        </div>

        <div className="space-y-6">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <h2 className="text-white font-semibold mb-1">{t("repoAccessTitle")}</h2>
            <p className="text-gray-500 text-sm mb-4">{t("repoAccessDesc")}</p>

            <div className="space-y-3">
              <label className={`flex items-start gap-3 p-4 rounded-lg border cursor-pointer transition-all ${repoScope === "public_only" ? "border-red-500/50 bg-red-500/5" : "border-gray-800 hover:border-gray-700"}`}>
                <input type="radio" name="repoScope" checked={repoScope === "public_only"} onChange={() => setRepoScope("public_only")} className="mt-0.5 text-red-600 focus:ring-red-500" />
                <div>
                  <span className="text-white text-sm font-medium">{t("publicOnly")}</span>
                  <p className="text-gray-500 text-xs mt-0.5">{t("publicOnlyDesc")}</p>
                </div>
              </label>

              <label className={`flex items-start gap-3 p-4 rounded-lg border cursor-pointer transition-all ${repoScope === "all" ? "border-red-500/50 bg-red-500/5" : "border-gray-800 hover:border-gray-700"}`}>
                <input type="radio" name="repoScope" checked={repoScope === "all"} onChange={() => setRepoScope("all")} className="mt-0.5 text-red-600 focus:ring-red-500" />
                <div>
                  <span className="text-white text-sm font-medium">{t("allRepos")}</span>
                  <p className="text-gray-500 text-xs mt-0.5">{t("allReposDesc")}</p>
                </div>
              </label>
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <h2 className="text-white font-semibold mb-1">{t("automationTitle")}</h2>
            <p className="text-gray-500 text-sm mb-4">{t("automationDesc")}</p>

            <div className="space-y-3">
              {FEATURE_KEYS.map((f) => (
                <div key={f.key} className="flex items-center justify-between p-3 rounded-lg border border-gray-800">
                  <div className="flex-1 min-w-0">
                    <span className="text-white text-sm font-medium">{t(f.labelKey)}</span>
                    <p className="text-gray-500 text-xs mt-0.5">{t(f.descKey)}</p>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={features[f.key]}
                    onClick={() => toggleFeature(f.key)}
                    className={`relative shrink-0 ml-3 w-10 h-6 rounded-full transition-colors ${features[f.key] ? "bg-red-600" : "bg-gray-700"}`}
                  >
                    <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${features[f.key] ? "translate-x-4" : ""}`} />
                  </button>
                </div>
              ))}
            </div>
          </div>

          <button onClick={handleComplete} disabled={loading} className="w-full py-3 bg-red-600 text-white rounded-lg font-medium hover:bg-red-700 transition-all disabled:opacity-50">
            {loading ? t("saving") : t("completeSetup")}
          </button>

          <p className="text-center text-gray-600 text-xs">{t("changeAnytime")}</p>
        </div>
      </div>
    </div>
  );
}
