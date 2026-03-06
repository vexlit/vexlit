"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { Profile } from "@/lib/types";
import { toast } from "sonner";

const FEATURES = [
  { key: "feature_pr_check", label: "PR Security Check", comingSoon: true },
  { key: "feature_auto_fix_pr", label: "Auto Fix PR", comingSoon: true },
  { key: "feature_dep_upgrade", label: "Dependency Upgrade PR", comingSoon: true },
  { key: "feature_code_analysis", label: "Static Code Analysis", comingSoon: false },
] as const;

export function SettingsClient({
  profile,
  email,
}: {
  profile: Profile | null;
  email: string;
}) {
  const router = useRouter();
  const [repoScope, setRepoScope] = useState<"public_only" | "all">(
    profile?.repo_scope ?? "public_only"
  );
  const [features, setFeatures] = useState<Record<string, boolean>>({
    feature_pr_check: profile?.feature_pr_check ?? true,
    feature_auto_fix_pr: profile?.feature_auto_fix_pr ?? true,
    feature_dep_upgrade: profile?.feature_dep_upgrade ?? true,
    feature_code_analysis: profile?.feature_code_analysis ?? true,
  });
  const [marketing, setMarketing] = useState(profile?.marketing_consent ?? false);
  const [saving, setSaving] = useState(false);

  const toggleFeature = (key: string) => {
    setFeatures((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await fetch("/api/profile", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_scope: repoScope,
          marketing_consent: marketing,
          ...features,
        }),
      });
      if (res.ok) {
        toast.success("Settings saved");
        router.refresh();
      } else {
        toast.error("Failed to save settings");
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 max-w-2xl">
      {/* Account */}
      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h2 className="text-white font-semibold mb-4">Account</h2>
        <div className="space-y-3">
          <div>
            <label className="text-gray-500 text-xs">Email</label>
            <p className="text-white text-sm">{email}</p>
          </div>
          {profile?.terms_accepted_at && (
            <div>
              <label className="text-gray-500 text-xs">Terms accepted</label>
              <p className="text-gray-400 text-sm">
                {profile.terms_version} — {new Date(profile.terms_accepted_at).toLocaleDateString()}
              </p>
            </div>
          )}
        </div>
      </section>

      {/* Repo scope */}
      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h2 className="text-white font-semibold mb-4">Repository Access</h2>
        <div className="space-y-3">
          <label
            className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
              repoScope === "public_only"
                ? "border-red-500/50 bg-red-500/5"
                : "border-gray-800 hover:border-gray-700"
            }`}
          >
            <input
              type="radio"
              name="scope"
              checked={repoScope === "public_only"}
              onChange={() => setRepoScope("public_only")}
              className="text-red-600 focus:ring-red-500"
            />
            <span className="text-white text-sm">Public repositories only</span>
          </label>
          <label
            className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
              repoScope === "all"
                ? "border-red-500/50 bg-red-500/5"
                : "border-gray-800 hover:border-gray-700"
            }`}
          >
            <input
              type="radio"
              name="scope"
              checked={repoScope === "all"}
              onChange={() => setRepoScope("all")}
              className="text-red-600 focus:ring-red-500"
            />
            <span className="text-white text-sm">All repositories (including private)</span>
          </label>
        </div>
      </section>

      {/* Feature toggles */}
      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h2 className="text-white font-semibold mb-4">Automation</h2>
        <div className="space-y-3">
          {FEATURES.map((f) => (
            <div
              key={f.key}
              className="flex items-center justify-between p-3 rounded-lg border border-gray-800"
            >
              <div className="flex items-center gap-2">
                <span className="text-white text-sm">{f.label}</span>
                {f.comingSoon && (
                  <span className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-yellow-500/15 text-yellow-400">
                    Coming Soon
                  </span>
                )}
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={features[f.key]}
                onClick={() => toggleFeature(f.key)}
                className={`relative w-10 h-6 rounded-full transition-colors ${
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
      </section>

      {/* Notifications */}
      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h2 className="text-white font-semibold mb-4">Notifications</h2>
        <label className="flex items-center justify-between p-3 rounded-lg border border-gray-800 cursor-pointer">
          <span className="text-white text-sm">Marketing emails</span>
          <button
            type="button"
            role="switch"
            aria-checked={marketing}
            onClick={() => setMarketing(!marketing)}
            className={`relative w-10 h-6 rounded-full transition-colors ${
              marketing ? "bg-red-600" : "bg-gray-700"
            }`}
          >
            <span
              className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${
                marketing ? "translate-x-4" : ""
              }`}
            />
          </button>
        </label>
      </section>

      {/* Save */}
      <button
        onClick={handleSave}
        disabled={saving}
        className="px-6 py-2.5 bg-red-600 text-white rounded-lg text-sm font-medium hover:bg-red-700 transition-all disabled:opacity-50"
      >
        {saving ? "Saving..." : "Save Changes"}
      </button>
    </div>
  );
}
