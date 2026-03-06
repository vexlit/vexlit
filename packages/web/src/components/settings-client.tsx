"use client";

import { useState } from "react";
import { useRouter } from "@/i18n/navigation";
import type { Profile } from "@/lib/types";
import { toast } from "sonner";

const FEATURES = [
  { key: "feature_pr_check", label: "PR Security Check" },
  { key: "feature_scheduled_scan", label: "Scheduled Security Scan" },
  { key: "feature_security_alerts", label: "Security Alerts" },
  { key: "feature_code_analysis", label: "Static Code Analysis" },
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
    feature_scheduled_scan: profile?.feature_scheduled_scan ?? true,
    feature_security_alerts: profile?.feature_security_alerts ?? true,
    feature_code_analysis: profile?.feature_code_analysis ?? true,
  });
  const [slackWebhook, setSlackWebhook] = useState(profile?.slack_webhook_url ?? "");
  const [discordWebhook, setDiscordWebhook] = useState(profile?.discord_webhook_url ?? "");
  const [marketing, setMarketing] = useState(profile?.marketing_consent ?? false);
  const [saving, setSaving] = useState(false);

  const toggleFeature = (key: string) => {
    setFeatures((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleSave = async () => {
    // Validate webhook URLs before saving
    if (
      slackWebhook &&
      !slackWebhook.startsWith("https://hooks.slack.com/") &&
      !slackWebhook.startsWith("https://hooks.slack-gov.com/")
    ) {
      toast.error("Invalid Slack webhook URL");
      return;
    }
    if (
      discordWebhook &&
      !discordWebhook.startsWith("https://discord.com/api/webhooks/") &&
      !discordWebhook.startsWith("https://discordapp.com/api/webhooks/")
    ) {
      toast.error("Invalid Discord webhook URL");
      return;
    }

    setSaving(true);
    try {
      const res = await fetch("/api/profile", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_scope: repoScope,
          marketing_consent: marketing,
          slack_webhook_url: slackWebhook || null,
          discord_webhook_url: discordWebhook || null,
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
              <span className="text-white text-sm">{f.label}</span>
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

      {/* Security Alerts */}
      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h2 className="text-white font-semibold mb-1">Security Alerts</h2>
        <p className="text-gray-500 text-xs mb-4">
          Receive scan results in Slack or Discord
        </p>
        <div className="space-y-3">
          <div>
            <label className="text-gray-500 text-xs">Slack Webhook URL</label>
            <input
              type="url"
              value={slackWebhook}
              onChange={(e) => setSlackWebhook(e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              className="w-full mt-1 px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm placeholder-gray-600 focus:outline-none focus:border-red-500"
            />
          </div>
          <div>
            <label className="text-gray-500 text-xs">Discord Webhook URL</label>
            <input
              type="url"
              value={discordWebhook}
              onChange={(e) => setDiscordWebhook(e.target.value)}
              placeholder="https://discord.com/api/webhooks/..."
              className="w-full mt-1 px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm placeholder-gray-600 focus:outline-none focus:border-red-500"
            />
          </div>
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
