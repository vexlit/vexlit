"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

const FEATURES = [
  {
    key: "feature_pr_check",
    label: "PR Security Check",
    description: "Automatically scan code when a pull request is created",
  },
  {
    key: "feature_scheduled_scan",
    label: "Scheduled Security Scan",
    description: "Run daily or weekly scans automatically",
  },
  {
    key: "feature_security_alerts",
    label: "Security Alerts",
    description: "Receive alerts in Slack, Discord, or email",
  },
  {
    key: "feature_code_analysis",
    label: "Static Code Analysis",
    description: "AST-based vulnerability detection across your codebase",
  },
] as const;

export default function OnboardingSetupPage() {
  const router = useRouter();
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
          <h1 className="text-2xl font-bold text-white">Setup Your Workspace</h1>
          <p className="text-gray-400 text-sm mt-2">
            Configure repository access and automation features
          </p>
        </div>

        <div className="space-y-6">
          {/* Step A: Repo scope */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <h2 className="text-white font-semibold mb-1">Repository Access</h2>
            <p className="text-gray-500 text-sm mb-4">
              Choose which repositories VEXLIT can access
            </p>

            <div className="space-y-3">
              <label
                className={`flex items-start gap-3 p-4 rounded-lg border cursor-pointer transition-all ${
                  repoScope === "public_only"
                    ? "border-red-500/50 bg-red-500/5"
                    : "border-gray-800 hover:border-gray-700"
                }`}
              >
                <input
                  type="radio"
                  name="repoScope"
                  checked={repoScope === "public_only"}
                  onChange={() => setRepoScope("public_only")}
                  className="mt-0.5 text-red-600 focus:ring-red-500"
                />
                <div>
                  <span className="text-white text-sm font-medium">Public repositories only</span>
                  <p className="text-gray-500 text-xs mt-0.5">
                    Scan only your public GitHub repositories
                  </p>
                </div>
              </label>

              <label
                className={`flex items-start gap-3 p-4 rounded-lg border cursor-pointer transition-all ${
                  repoScope === "all"
                    ? "border-red-500/50 bg-red-500/5"
                    : "border-gray-800 hover:border-gray-700"
                }`}
              >
                <input
                  type="radio"
                  name="repoScope"
                  checked={repoScope === "all"}
                  onChange={() => setRepoScope("all")}
                  className="mt-0.5 text-red-600 focus:ring-red-500"
                />
                <div>
                  <span className="text-white text-sm font-medium">All repositories</span>
                  <p className="text-gray-500 text-xs mt-0.5">
                    Include private repositories for comprehensive scanning
                  </p>
                </div>
              </label>
            </div>
          </div>

          {/* Step B: Feature toggles */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <h2 className="text-white font-semibold mb-1">Automation Features</h2>
            <p className="text-gray-500 text-sm mb-4">
              Enable or disable features — you can change these later in Settings
            </p>

            <div className="space-y-3">
              {FEATURES.map((f) => (
                <div
                  key={f.key}
                  className="flex items-center justify-between p-3 rounded-lg border border-gray-800"
                >
                  <div className="flex-1 min-w-0">
                    <span className="text-white text-sm font-medium">{f.label}</span>
                    <p className="text-gray-500 text-xs mt-0.5">{f.description}</p>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={features[f.key]}
                    onClick={() => toggleFeature(f.key)}
                    className={`relative shrink-0 ml-3 w-10 h-6 rounded-full transition-colors ${
                      features[f.key] ? "bg-red-600" : "bg-gray-700"
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${
                        features[f.key] ? "translate-x-4" : ""
                      }`}
                    />
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Submit */}
          <button
            onClick={handleComplete}
            disabled={loading}
            className="w-full py-3 bg-red-600 text-white rounded-lg font-medium hover:bg-red-700 transition-all disabled:opacity-50"
          >
            {loading ? "Saving..." : "Complete Setup"}
          </button>

          <p className="text-center text-gray-600 text-xs">
            You can change these settings anytime from the dashboard
          </p>
        </div>
      </div>
    </div>
  );
}
