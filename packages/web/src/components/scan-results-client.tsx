"use client";

import { useState, useMemo } from "react";
import { SeverityBadge } from "./severity-badge";
import { AiExplainButton } from "./ai-explain-button";
import { AiFixButton } from "./ai-fix-button";
import { toast } from "sonner";
import type { Vulnerability } from "@/lib/types";

function ConfidenceBadge({ confidence }: { confidence: "high" | "medium" | "low" }) {
  const styles: Record<string, string> = {
    high: "bg-green-900/40 text-green-400 border-green-800",
    medium: "bg-yellow-900/40 text-yellow-400 border-yellow-800",
    low: "bg-gray-800 text-gray-400 border-gray-700",
  };
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${styles[confidence] ?? styles.medium}`}>
      {confidence}
    </span>
  );
}

const KEYWORDS = new Set([
  "const","let","var","function","return","if","else","for","while",
  "import","export","from","require","new","async","await","class","extends",
]);

function tokenize(code: string): { text: string; type: "keyword" | "string" | "number" | "plain" }[] {
  const tokens: { text: string; type: "keyword" | "string" | "number" | "plain" }[] = [];
  // Match strings, keywords, numbers, or anything else
  const regex = /(["'`])(?:(?!\1|\\).|\\.)*?\1|\b[a-zA-Z_]\w*\b|\b\d+\b|[^"'`\w]+/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(code)) !== null) {
    const t = match[0];
    if (/^["'`]/.test(t)) {
      tokens.push({ text: t, type: "string" });
    } else if (KEYWORDS.has(t)) {
      tokens.push({ text: t, type: "keyword" });
    } else if (/^\d+$/.test(t)) {
      tokens.push({ text: t, type: "number" });
    } else {
      tokens.push({ text: t, type: "plain" });
    }
  }
  return tokens;
}

const TOKEN_COLORS = {
  keyword: "text-purple-400",
  string: "text-green-400",
  number: "text-orange-400",
  plain: "text-gray-300",
};

function CodeSnippet({ line, code }: { line: number; code: string }) {
  const tokens = tokenize(code);
  return (
    <pre className="mt-2 px-3 py-2 bg-gray-950 rounded text-sm font-mono overflow-x-auto">
      <span className="text-gray-600 select-none">{line} | </span>
      {tokens.map((t, i) => (
        <span key={i} className={TOKEN_COLORS[t.type]}>{t.text}</span>
      ))}
    </pre>
  );
}

interface Props {
  scanId: string;
  vulns: Vulnerability[];
  sarifJson: unknown | null;
}

export function ScanResultsClient({ scanId, vulns, sarifJson }: Props) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [fileFilter, setFileFilter] = useState<string>("all");
  const [ruleFilter, setRuleFilter] = useState<string>("all");
  const [exploitableOnly, setExploitableOnly] = useState(false);
  const [expandedVuln, setExpandedVuln] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"all" | "sast" | "sca">("all");
  const [hideDevDeps, setHideDevDeps] = useState(false);

  // Separate SCA and SAST vulns
  const scaVulns = useMemo(() => vulns.filter((v) => v.rule_id.startsWith("SCA-")), [vulns]);
  const sastVulns = useMemo(() => vulns.filter((v) => !v.rule_id.startsWith("SCA-")), [vulns]);

  // Unique values for filter dropdowns
  const files = useMemo(() => [...new Set(vulns.map((v) => v.file_path))], [vulns]);
  const rules = useMemo(() => [...new Set(vulns.map((v) => v.rule_name))], [vulns]);

  const exploitableCount = useMemo(
    () => vulns.filter((v) => v.severity === "critical" && v.confidence === "high").length,
    [vulns]
  );

  // Filtered + searched vulns
  const filtered = useMemo(() => {
    const base = activeTab === "sast" ? sastVulns : activeTab === "sca" ? scaVulns : vulns;
    return base.filter((v) => {
      if (exploitableOnly && (v.severity !== "critical" || v.confidence !== "high")) return false;
      if (severityFilter !== "all" && v.severity !== severityFilter) return false;
      if (fileFilter !== "all" && v.file_path !== fileFilter) return false;
      if (ruleFilter !== "all" && v.rule_name !== ruleFilter) return false;
      if (hideDevDeps && v.rule_id.startsWith("SCA-") && v.rule_name.includes("(dev)")) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          v.message.toLowerCase().includes(q) ||
          v.rule_name.toLowerCase().includes(q) ||
          v.file_path.toLowerCase().includes(q) ||
          v.snippet?.toLowerCase().includes(q) ||
          v.cwe?.toLowerCase().includes(q) ||
          false
        );
      }
      return true;
    });
  }, [vulns, sastVulns, scaVulns, activeTab, severityFilter, fileFilter, ruleFilter, search, exploitableOnly, hideDevDeps]);

  // Split filtered into SAST (group by file) and SCA (group by package)
  const filteredSast = useMemo(() => filtered.filter((v) => !v.rule_id.startsWith("SCA-")), [filtered]);
  const filteredSca = useMemo(() => filtered.filter((v) => v.rule_id.startsWith("SCA-")), [filtered]);

  // Group SAST by file
  const fileGroups = useMemo(() => {
    const groups = new Map<string, Vulnerability[]>();
    for (const v of filteredSast) {
      const existing = groups.get(v.file_path) ?? [];
      existing.push(v);
      groups.set(v.file_path, existing);
    }
    return groups;
  }, [filteredSast]);

  // Group SCA by package name (extracted from rule_name: "Vulnerable dependency: lodash" or "Vulnerable dependency: lodash (dev)")
  const scaPackageGroups = useMemo(() => {
    const groups = new Map<string, Vulnerability[]>();
    for (const v of filteredSca) {
      const pkgName = v.rule_name.replace("Vulnerable dependency: ", "").replace(" (dev)", "");
      const existing = groups.get(pkgName) ?? [];
      existing.push(v);
      groups.set(pkgName, existing);
    }
    return groups;
  }, [filteredSca]);

  const handleSarifDownload = () => {
    if (!sarifJson) {
      toast.error("SARIF data not available for this scan");
      return;
    }
    const blob = new Blob([JSON.stringify(sarifJson, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `vexlit-scan-${scanId.slice(0, 8)}.sarif`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("SARIF file downloaded");
  };

  return (
    <div className="space-y-4">
      {/* SAST / SCA tabs */}
      {scaVulns.length > 0 && (
        <div className="flex items-center gap-2">
          {(["all", "sast", "sca"] as const).map((tab) => {
            const label = tab === "all" ? `All (${vulns.length})` : tab === "sast" ? `SAST (${sastVulns.length})` : `SCA (${scaVulns.length})`;
            return (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
                  activeTab === tab
                    ? "bg-white/10 text-white"
                    : "text-gray-500 hover:text-gray-300"
                }`}
              >
                {label}
              </button>
            );
          })}

          {/* Hide dev deps toggle (only when SCA vulns exist) */}
          {scaVulns.some((v) => v.rule_name.includes("(dev)")) && (
            <button
              onClick={() => setHideDevDeps(!hideDevDeps)}
              className={`ml-auto px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                hideDevDeps
                  ? "bg-purple-600 text-white"
                  : "text-gray-500 border border-gray-800 hover:text-gray-300"
              }`}
            >
              {hideDevDeps ? "Dev deps hidden" : "Hide dev deps"}
            </button>
          )}
        </div>
      )}

      {/* Exploitable only toggle */}
      {exploitableCount > 0 && (
        <button
          onClick={() => setExploitableOnly(!exploitableOnly)}
          className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all w-fit ${
            exploitableOnly
              ? "bg-red-600 text-white shadow-lg shadow-red-600/20"
              : "bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20"
          }`}
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
          </svg>
          Show exploitable only ({exploitableCount})
        </button>
      )}

      {/* Filter bar */}
      <div className="flex flex-col sm:flex-row gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <svg
            className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search vulnerabilities..."
            aria-label="Search vulnerabilities"
            className="w-full pl-9 pr-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-gray-700"
          />
        </div>

        {/* Severity filter */}
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-sm text-gray-300 focus:outline-none focus:border-gray-700"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="warning">Warning</option>
          <option value="info">Info</option>
        </select>

        {/* File filter */}
        <select
          value={fileFilter}
          onChange={(e) => setFileFilter(e.target.value)}
          className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-sm text-gray-300 focus:outline-none focus:border-gray-700 max-w-48"
        >
          <option value="all">All Files</option>
          {files.map((f) => (
            <option key={f} value={f}>
              {f.split("/").pop()}
            </option>
          ))}
        </select>

        {/* Rule filter */}
        <select
          value={ruleFilter}
          onChange={(e) => setRuleFilter(e.target.value)}
          className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-sm text-gray-300 focus:outline-none focus:border-gray-700 max-w-48"
        >
          <option value="all">All Rules</option>
          {rules.map((r) => (
            <option key={r} value={r}>{r}</option>
          ))}
        </select>

        {/* SARIF Download */}
        <button
          onClick={handleSarifDownload}
          className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-sm text-gray-300 hover:border-gray-700 hover:text-white transition-colors flex items-center gap-2 whitespace-nowrap"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
          </svg>
          SARIF
        </button>
      </div>

      {/* Result count */}
      <p className="text-gray-500 text-sm">
        Showing {filtered.length} of {vulns.length} vulnerabilities
      </p>

      {/* Results */}
      {filtered.length === 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center">
          <p className="text-gray-400">No vulnerabilities match your filters.</p>
        </div>
      )}

      {/* SCA results grouped by package */}
      {filteredSca.length > 0 && (activeTab === "all" || activeTab === "sca") && (
        <>
          {activeTab === "all" && filteredSast.length > 0 && (
            <div className="flex items-center gap-2 pt-2">
              <svg className="w-4 h-4 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
              </svg>
              <span className="text-sm font-medium text-gray-300">
                SCA — Vulnerable Dependencies ({filteredSca.length})
              </span>
            </div>
          )}
          {Array.from(scaPackageGroups.entries()).map(([pkgName, pkgVulns]) => {
            const isDev = pkgVulns.some((v) => v.rule_name.includes("(dev)"));
            const versions = [...new Set(pkgVulns.map((v) => {
              const match = v.message.match(/^[^@]+@([^\s(]+)/);
              return match?.[1] ?? "";
            }))].filter(Boolean);
            const maxSeverity = pkgVulns.some((v) => v.severity === "critical") ? "critical"
              : pkgVulns.some((v) => v.severity === "warning") ? "warning" : "info";

            return (
              <div
                key={pkgName}
                className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
              >
                <div className="px-4 py-3 border-b border-gray-800 bg-gray-900/50 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={maxSeverity} />
                    <span className="text-gray-200 text-sm font-medium">{pkgName}</span>
                    {versions.length > 0 && (
                      <span className="text-gray-500 text-xs font-mono">@{versions.join(", @")}</span>
                    )}
                    {isDev && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-purple-900/40 text-purple-400 border border-purple-800">
                        dev
                      </span>
                    )}
                  </div>
                  <span className="text-gray-600 text-xs">
                    {pkgVulns.length} CVE{pkgVulns.length > 1 ? "s" : ""}
                  </span>
                </div>

                <div className="divide-y divide-gray-800">
                  {pkgVulns.map((v) => {
                    const isExpanded = expandedVuln === v.id;
                    const cveId = v.rule_id.replace("SCA-", "");
                    return (
                      <div key={v.id} className="px-4 py-3">
                        <div
                          className="flex items-start gap-3 cursor-pointer"
                          onClick={() => setExpandedVuln(isExpanded ? null : v.id)}
                        >
                          <SeverityBadge severity={v.severity} />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-white text-sm font-medium font-mono">{cveId}</span>
                              <span className="text-gray-600 text-xs">{v.file_path}:{v.line}</span>
                              <svg
                                className={`w-4 h-4 text-gray-500 transition-transform ml-auto ${isExpanded ? "rotate-180" : ""}`}
                                fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
                              >
                                <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                              </svg>
                            </div>
                            <p className="text-gray-400 text-sm mt-1">{v.message}</p>
                          </div>
                        </div>

                        {isExpanded && (
                          <div className="mt-3 ml-10 space-y-3 border-l-2 border-gray-800 pl-4">
                            {v.suggestion && (
                              <div>
                                <p className="text-xs text-gray-500 uppercase font-medium mb-1">Remediation</p>
                                <p className="text-sm text-green-400/80">{v.suggestion}</p>
                              </div>
                            )}
                            <div className="flex gap-4">
                              {v.cwe && (
                                <div>
                                  <p className="text-xs text-gray-500 uppercase font-medium mb-1">CWE</p>
                                  <a
                                    href={`https://cwe.mitre.org/data/definitions/${v.cwe.replace("CWE-", "")}.html`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-sm text-blue-400 hover:underline"
                                  >
                                    {v.cwe}
                                  </a>
                                </div>
                              )}
                              {v.owasp && (
                                <div>
                                  <p className="text-xs text-gray-500 uppercase font-medium mb-1">OWASP</p>
                                  <span className="text-sm text-gray-300">{v.owasp}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </>
      )}

      {/* SAST results grouped by file */}
      {filteredSast.length > 0 && (activeTab === "all" || activeTab === "sast") && (
        <>
          {activeTab === "all" && filteredSca.length > 0 && (
            <div className="flex items-center gap-2 pt-2">
              <svg className="w-4 h-4 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
              </svg>
              <span className="text-sm font-medium text-gray-300">
                SAST — Code Vulnerabilities ({filteredSast.length})
              </span>
            </div>
          )}
          {Array.from(fileGroups.entries()).map(([filePath, fileVulns]) => (
            <div
              key={filePath}
              className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
            >
              <div className="px-4 py-3 border-b border-gray-800 bg-gray-900/50 flex items-center justify-between">
                <div>
                  <span className="text-gray-300 text-sm font-mono">{filePath}</span>
                  <span className="text-gray-600 text-xs ml-2">
                    {fileVulns.length} issue{fileVulns.length > 1 ? "s" : ""}
                  </span>
                </div>
              </div>

              <div className="divide-y divide-gray-800">
                {fileVulns.map((v) => {
                  const isExpanded = expandedVuln === v.id;
                  return (
                    <div key={v.id} className="px-4 py-4">
                      <div
                        className="flex items-start gap-3 cursor-pointer"
                        onClick={() => setExpandedVuln(isExpanded ? null : v.id)}
                      >
                        <SeverityBadge severity={v.severity} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-white text-sm font-medium">
                              {v.rule_name}
                            </span>
                            <ConfidenceBadge confidence={v.confidence} />
                            <span className="text-gray-600 text-xs">
                              Line {v.line}:{v.column}
                            </span>
                            <svg
                              className={`w-4 h-4 text-gray-500 transition-transform ml-auto ${isExpanded ? "rotate-180" : ""}`}
                              fill="none"
                              viewBox="0 0 24 24"
                              stroke="currentColor"
                              strokeWidth={2}
                            >
                              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                            </svg>
                          </div>
                          <p className="text-gray-400 text-sm mt-1">{v.message}</p>

                          {v.snippet && <CodeSnippet line={v.line} code={v.snippet} />}
                        </div>
                      </div>

                      {/* Expanded detail panel */}
                      {isExpanded && (
                        <div className="mt-4 ml-10 space-y-3 border-l-2 border-gray-800 pl-4">
                          {v.suggestion && (
                            <div>
                              <p className="text-xs text-gray-500 uppercase font-medium mb-1">Fix Suggestion</p>
                              <p className="text-sm text-green-400/80">{v.suggestion}</p>
                            </div>
                          )}
                          <div className="flex gap-4">
                            {v.cwe && (
                              <div>
                                <p className="text-xs text-gray-500 uppercase font-medium mb-1">CWE</p>
                                <a
                                  href={`https://cwe.mitre.org/data/definitions/${v.cwe.replace("CWE-", "")}.html`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-sm text-blue-400 hover:underline"
                                >
                                  {v.cwe}
                                </a>
                              </div>
                            )}
                            {v.owasp && (
                              <div>
                                <p className="text-xs text-gray-500 uppercase font-medium mb-1">OWASP</p>
                                <span className="text-sm text-gray-300">{v.owasp}</span>
                              </div>
                            )}
                          </div>

                          {/* AI buttons */}
                          <div className="flex gap-2 pt-2">
                            <AiExplainButton
                              scanId={scanId}
                              vulnId={v.id}
                              ruleName={v.rule_name}
                              severity={v.severity}
                              message={v.message}
                              filePath={v.file_path}
                              line={v.line}
                              snippet={v.snippet}
                              cwe={v.cwe}
                              owasp={v.owasp}
                            />
                            <AiFixButton
                              scanId={scanId}
                              vulnId={v.id}
                              ruleName={v.rule_name}
                              message={v.message}
                              filePath={v.file_path}
                              line={v.line}
                              snippet={v.snippet}
                              suggestion={v.suggestion}
                            />
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </>
      )}
    </div>
  );
}
