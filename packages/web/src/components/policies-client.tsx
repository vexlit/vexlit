"use client";

import { useState, useEffect, useCallback } from "react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

interface PolicyRow {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  conditions: Record<string, unknown>;
  action: "block" | "warn" | "ignore";
  project_id: string | null;
  created_at: string;
}

const SEVERITY_OPTIONS = [
  { value: "critical", label: "Critical" },
  { value: "warning", label: "Warning" },
  { value: "info", label: "Info" },
];

const SOURCE_OPTIONS = [
  { value: "", label: "All" },
  { value: "sast", label: "SAST" },
  { value: "sca", label: "SCA" },
  { value: "license", label: "License" },
];

const ACTION_OPTIONS = [
  { value: "block", label: "Block" },
  { value: "warn", label: "Warn" },
  { value: "ignore", label: "Ignore" },
];

export function PoliciesClient() {
  const t = useTranslations("policies");
  const [policies, setPolicies] = useState<PolicyRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);

  // Form state
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [action, setAction] = useState<"block" | "warn" | "ignore">("warn");
  const [severityGte, setSeverityGte] = useState("critical");
  const [source, setSource] = useState("");
  const [reachableOnly, setReachableOnly] = useState(false);
  const [saving, setSaving] = useState(false);

  const fetchPolicies = useCallback(async () => {
    try {
      const res = await fetch("/api/policies");
      const data = await res.json();
      if (res.ok) setPolicies(data.policies ?? []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPolicies();
  }, [fetchPolicies]);

  const resetForm = () => {
    setName("");
    setDescription("");
    setAction("warn");
    setSeverityGte("critical");
    setSource("");
    setReachableOnly(false);
    setEditingId(null);
    setShowForm(false);
  };

  const handleEdit = (p: PolicyRow) => {
    setName(p.name);
    setDescription(p.description);
    setAction(p.action);
    const cond = p.conditions;
    setSeverityGte((cond.severity_gte as string) ?? "critical");
    setSource((cond.source as string) ?? "");
    setReachableOnly((cond.reachable_only as boolean) ?? false);
    setEditingId(p.id);
    setShowForm(true);
  };

  const handleSave = async () => {
    if (!name.trim()) return;
    setSaving(true);

    const conditions: Record<string, unknown> = {};
    if (severityGte) conditions.severity_gte = severityGte;
    if (source) conditions.source = source;
    if (reachableOnly) conditions.reachable_only = true;

    try {
      const url = editingId ? `/api/policies/${editingId}` : "/api/policies";
      const method = editingId ? "PUT" : "POST";
      const res = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, description, conditions, action }),
      });
      if (res.ok) {
        toast.success(editingId ? t("policyUpdated") : t("policyCreated"));
        resetForm();
        fetchPolicies();
      } else {
        const data = await res.json();
        toast.error(data.error ?? "Failed");
      }
    } catch {
      toast.error("Network error");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      const res = await fetch(`/api/policies/${id}`, { method: "DELETE" });
      if (res.ok) {
        toast.success(t("policyDeleted"));
        fetchPolicies();
      }
    } catch {
      toast.error("Network error");
    }
  };

  const handleToggle = async (p: PolicyRow) => {
    try {
      await fetch(`/api/policies/${p.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !p.enabled }),
      });
      fetchPolicies();
    } catch {
      toast.error("Network error");
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Create/Edit form */}
      {showForm ? (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
          <h3 className="text-white font-semibold">
            {editingId ? t("editPolicy") : t("createPolicy")}
          </h3>

          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <label className="block text-gray-400 text-xs mb-1">{t("policyName")}</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-red-500"
                placeholder={t("policyNamePlaceholder")}
              />
            </div>
            <div>
              <label className="block text-gray-400 text-xs mb-1">{t("action")}</label>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value as "block" | "warn" | "ignore")}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-red-500"
              >
                {ACTION_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-gray-400 text-xs mb-1">{t("descriptionLabel")}</label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-red-500"
              placeholder={t("descriptionPlaceholder")}
            />
          </div>

          <div className="border-t border-gray-800 pt-4">
            <p className="text-gray-400 text-xs font-semibold uppercase tracking-wider mb-3">
              {t("conditions")}
            </p>
            <div className="grid md:grid-cols-3 gap-4">
              <div>
                <label className="block text-gray-400 text-xs mb-1">{t("minSeverity")}</label>
                <select
                  value={severityGte}
                  onChange={(e) => setSeverityGte(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-red-500"
                >
                  {SEVERITY_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-gray-400 text-xs mb-1">{t("source")}</label>
                <select
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-red-500"
                >
                  {SOURCE_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-end">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={reachableOnly}
                    onChange={(e) => setReachableOnly(e.target.checked)}
                    className="w-4 h-4 rounded border-gray-600 bg-gray-800 text-red-500 focus:ring-red-500"
                  />
                  <span className="text-gray-300 text-sm">{t("reachableOnly")}</span>
                </label>
              </div>
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button
              onClick={resetForm}
              className="px-4 py-2 text-gray-400 text-sm hover:text-white transition-colors"
            >
              {t("cancel")}
            </button>
            <button
              onClick={handleSave}
              disabled={saving || !name.trim()}
              className="px-4 py-2 bg-red-600 text-white text-sm font-medium rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50"
            >
              {saving ? t("saving") : editingId ? t("update") : t("create")}
            </button>
          </div>
        </div>
      ) : (
        <button
          onClick={() => setShowForm(true)}
          className="inline-flex items-center gap-2 px-4 py-2 bg-red-600 text-white text-sm font-medium rounded-lg hover:bg-red-700 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
          </svg>
          {t("addPolicy")}
        </button>
      )}

      {/* Policy list */}
      {policies.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center">
          <svg className="w-12 h-12 text-gray-700 mx-auto mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
          </svg>
          <p className="text-gray-400 text-sm">{t("noPolicies")}</p>
          <p className="text-gray-600 text-xs mt-1">{t("noPoliciesDesc")}</p>
        </div>
      ) : (
        <div className="space-y-3">
          {policies.map((p) => (
            <div
              key={p.id}
              className={`bg-gray-900 border rounded-xl p-4 transition-colors ${
                p.enabled
                  ? "border-gray-800"
                  : "border-gray-800/50 opacity-60"
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3 min-w-0">
                  <button
                    onClick={() => handleToggle(p)}
                    className={`w-9 h-5 rounded-full transition-colors relative flex-shrink-0 ${
                      p.enabled ? "bg-red-600" : "bg-gray-700"
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
                        p.enabled ? "left-4" : "left-0.5"
                      }`}
                    />
                  </button>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-white text-sm font-medium truncate">
                        {p.name}
                      </span>
                      <ActionBadge action={p.action} />
                    </div>
                    {p.description && (
                      <p className="text-gray-500 text-xs mt-0.5 truncate">
                        {p.description}
                      </p>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0 ml-3">
                  <ConditionTags conditions={p.conditions} />
                  <button
                    onClick={() => handleEdit(p)}
                    className="p-1.5 text-gray-500 hover:text-white transition-colors"
                    title="Edit"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
                    </svg>
                  </button>
                  <button
                    onClick={() => handleDelete(p.id)}
                    className="p-1.5 text-gray-500 hover:text-red-400 transition-colors"
                    title="Delete"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
                    </svg>
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ActionBadge({ action }: { action: string }) {
  const styles: Record<string, string> = {
    block: "bg-red-900/40 text-red-400 border-red-800",
    warn: "bg-yellow-900/40 text-yellow-400 border-yellow-800",
    ignore: "bg-gray-800 text-gray-400 border-gray-700",
  };
  return (
    <span
      className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${
        styles[action] ?? styles.warn
      }`}
    >
      {action}
    </span>
  );
}

function ConditionTags({ conditions }: { conditions: Record<string, unknown> }) {
  const tags: string[] = [];
  if (conditions.severity_gte) tags.push(`≥ ${conditions.severity_gte}`);
  if (conditions.source) tags.push(String(conditions.source).toUpperCase());
  if (conditions.reachable_only) tags.push("reachable");
  if (!tags.length) return null;
  return (
    <div className="hidden sm:flex items-center gap-1">
      {tags.map((tag) => (
        <span
          key={tag}
          className="px-1.5 py-0.5 rounded bg-gray-800 text-gray-500 text-[10px] font-medium"
        >
          {tag}
        </span>
      ))}
    </div>
  );
}
