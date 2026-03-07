"use client";

import { useState, useMemo, useCallback } from "react";
import { useTranslations } from "next-intl";
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

export interface DepEntry {
  name: string;
  version: string;
  ecosystem: string;
  dev?: boolean;
  license?: string;
  declaredRange?: string;
}

export interface DepGraphData {
  edges: Record<string, string[]>;
  ranges: Record<string, string>;
}

/** Trace reverse dependency chain: find how a package ended up in the project */
function traceDepChain(
  graph: DepGraphData,
  targetKey: string,
  maxDepth = 5
): string[][] {
  // Build reverse map: child -> parents
  const reverseEdges = new Map<string, string[]>();
  for (const [parent, children] of Object.entries(graph.edges)) {
    for (const child of children) {
      const parents = reverseEdges.get(child) ?? [];
      parents.push(parent);
      reverseEdges.set(child, parents);
    }
  }

  // BFS upward from target to find paths to root (packages with no parents)
  const paths: string[][] = [];
  const queue: { key: string; path: string[] }[] = [{ key: targetKey, path: [targetKey] }];
  const visited = new Set<string>();

  while (queue.length > 0 && paths.length < 3) {
    const item = queue.shift()!;
    if (item.path.length > maxDepth) continue;

    const parents = reverseEdges.get(item.key);
    if (!parents || parents.length === 0) {
      // Root — this is a direct dependency
      paths.push(item.path);
      continue;
    }

    for (const parent of parents) {
      if (visited.has(parent)) continue;
      visited.add(parent);
      queue.push({ key: parent, path: [...item.path, parent] });
    }
  }

  return paths;
}

function DepChain({ graph, ecosystem, name, version }: {
  graph: DepGraphData;
  ecosystem: string;
  name: string;
  version: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const targetKey = `${ecosystem}:${name}@${version}`;
  const chains = useMemo(() => traceDepChain(graph, targetKey), [graph, targetKey]);
  const range = graph.ranges[targetKey];

  if (chains.length === 0 && !range) return null;

  return (
    <div className="mt-2">
      {range && (
        <p className="text-xs text-gray-500 mb-1">
          <span className="text-gray-600">Declared:</span>{" "}
          <span className="text-gray-400 font-mono">{range}</span>
          <span className="text-gray-600 mx-1">&rarr;</span>
          <span className="text-white font-mono">{version}</span>
        </p>
      )}
      {chains.length > 0 && (
        <>
          <button
            onClick={() => setExpanded(!expanded)}
            className="text-xs text-blue-400 hover:text-blue-300 transition-colors flex items-center gap-1"
          >
            <svg className={`w-3 h-3 transition-transform ${expanded ? "rotate-90" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
            </svg>
            Dependency chain ({chains.length})
          </button>
          {expanded && (
            <div className="mt-1.5 space-y-1.5">
              {chains.map((chain, ci) => (
                <div key={ci} className="text-xs font-mono pl-2 border-l border-gray-800">
                  {[...chain].reverse().map((key, i) => {
                    const depRange = graph.ranges[key];
                    const depName = key.replace(/^[^:]+:/, "");
                    const isTarget = i === chain.length - 1;
                    return (
                      <div key={key} className="flex items-center gap-1" style={{ paddingLeft: `${i * 12}px` }}>
                        {i > 0 && <span className="text-gray-700">└─</span>}
                        <span className={isTarget ? "text-red-400" : "text-gray-300"}>{depName}</span>
                        {depRange && !isTarget && (
                          <span className="text-gray-600">({depRange})</span>
                        )}
                        {i === 0 && <span className="text-gray-600 italic">(direct)</span>}
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

interface Props {
  scanId: string;
  vulns: Vulnerability[];
  sarifJson: unknown | null;
  depsJson?: DepEntry[] | null;
  depGraphJson?: DepGraphData | null;
  projectName?: string;
}

export function ScanResultsClient({ scanId, vulns, sarifJson, depsJson, depGraphJson, projectName }: Props) {
  const t = useTranslations("scanResults");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [fileFilter, setFileFilter] = useState<string>("all");
  const [ruleFilter, setRuleFilter] = useState<string>("all");
  const [exploitableOnly, setExploitableOnly] = useState(false);
  const [expandedVuln, setExpandedVuln] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"all" | "sast" | "sca">("all");
  const [hideDevDeps, setHideDevDeps] = useState(false);

  // Separate SCA and SAST vulns (exclude SCA-SKIPPED and SCA-META markers from vuln lists)
  const scaSkipped = useMemo(() => vulns.find((v) => v.rule_id === "SCA-SKIPPED"), [vulns]);
  const scaMeta = useMemo(() => vulns.find((v) => v.rule_id === "SCA-META"), [vulns]);
  const depCount = scaMeta ? parseInt(scaMeta.message, 10) || 0 : 0;
  const realVulns = useMemo(() => vulns.filter((v) => v.rule_id !== "SCA-SKIPPED" && v.rule_id !== "SCA-META"), [vulns]);
  const scaVulns = useMemo(() => realVulns.filter((v) => v.rule_id.startsWith("SCA-")), [realVulns]);
  const sastVulns = useMemo(() => realVulns.filter((v) => !v.rule_id.startsWith("SCA-")), [realVulns]);

  // Unique values for filter dropdowns
  const files = useMemo(() => [...new Set(realVulns.map((v) => v.file_path))], [realVulns]);
  const rules = useMemo(() => [...new Set(realVulns.map((v) => v.rule_name))], [realVulns]);

  const exploitableCount = useMemo(
    () => realVulns.filter((v) => v.severity === "critical" && v.confidence === "high").length,
    [realVulns]
  );

  // Filtered + searched vulns
  const filtered = useMemo(() => {
    const base = activeTab === "sast" ? sastVulns : activeTab === "sca" ? scaVulns : realVulns;
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
  }, [realVulns, sastVulns, scaVulns, activeTab, severityFilter, fileFilter, ruleFilter, search, exploitableOnly, hideDevDeps]);

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
      toast.error(t("sarifNotAvailable"));
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
    toast.success(t("sarifDownloaded"));
  };

  const handleSbomDownload = () => {
    if (!depsJson || depsJson.length === 0) {
      toast.error(t("sbomNotAvailable"));
      return;
    }
    const purlMap: Record<string, (n: string, v: string) => string> = {
      npm: (n, v) => `pkg:npm/${n.startsWith("@") ? "%40" + n.slice(1) : n}@${v}`,
      PyPI: (n, v) => `pkg:pypi/${n.toLowerCase()}@${v}`,
      Go: (n, v) => `pkg:golang/${n}@${v}`,
      "crates.io": (n, v) => `pkg:cargo/${n}@${v}`,
    };
    const sbom = {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      serialNumber: `urn:uuid:${crypto.randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [{ vendor: "Vexlit", name: "Vexlit SCA", version: "1.0.0" }],
        ...(projectName ? { component: { type: "application", name: projectName } } : {}),
      },
      components: depsJson.map((d) => {
        const purl = (purlMap[d.ecosystem] ?? purlMap.npm)(d.name, d.version);
        return {
          type: "library",
          "bom-ref": purl,
          name: d.name,
          version: d.version,
          purl,
          ...(d.license ? { licenses: [{ license: { id: d.license } }] } : {}),
          ...(d.dev ? { scope: "excluded" } : {}),
        };
      }),
    };
    const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `vexlit-sbom-${scanId.slice(0, 8)}.cdx.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(t("sbomDownloaded"));
  };

  // License vulns
  const licenseVulns = useMemo(
    () => realVulns.filter((v) => v.rule_id.startsWith("LICENSE-")),
    [realVulns]
  );

  // License summary from depsJson
  const licenseSummary = useMemo(() => {
    if (!depsJson) return [];
    const counts = new Map<string, number>();
    for (const d of depsJson) {
      const lic = d.license || "Unknown";
      counts.set(lic, (counts.get(lic) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  }, [depsJson]);

  return (
    <div className="space-y-4">
      {/* SAST / SCA tabs */}
      {scaVulns.length > 0 && (
        <div className="flex items-center gap-2">
          {(["all", "sast", "sca"] as const).map((tab) => {
            const label = tab === "all" ? t("allTab", { count: realVulns.length }) : tab === "sast" ? t("sastTab", { count: sastVulns.length }) : t("scaTab", { count: scaVulns.length });
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
              {hideDevDeps ? t("devDepsHidden") : t("hideDevDeps")}
            </button>
          )}
        </div>
      )}

      {/* Dependency scan summary */}
      {depCount > 0 && !scaSkipped && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3 flex items-center gap-3">
          <svg className="w-5 h-5 text-blue-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
          </svg>
          <div>
            <p className="text-gray-300 text-sm">
              {t("depScanned", { count: depCount })}
              {scaVulns.length > 0 && (
                <span className="text-red-400 ml-2 font-medium">{t("vulnerable", { count: scaVulns.length })}</span>
              )}
              {scaVulns.length === 0 && (
                <span className="text-green-400 ml-2 font-medium">{t("zeroVulnerable")}</span>
              )}
            </p>
            {licenseSummary.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-1.5">
                {licenseSummary.map(([lic, count]) => (
                  <span key={lic} className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-gray-800 text-gray-400 border border-gray-700">
                    {lic}: {count}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* License warnings */}
      {licenseVulns.length > 0 && (
        <div className="bg-orange-500/10 border border-orange-500/20 rounded-xl px-4 py-3">
          <div className="flex items-center gap-2 mb-2">
            <svg className="w-5 h-5 text-orange-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
            </svg>
            <span className="text-orange-400 text-sm font-medium">
              {t("licenseWarning", { count: licenseVulns.length })}
            </span>
          </div>
          <div className="space-y-1 ml-7">
            {licenseVulns.slice(0, 5).map((v) => {
              const licMatch = v.snippet?.match(/License: (.+)$/);
              const lic = licMatch?.[1] ?? "";
              const pkg = v.rule_name.replace("Copyleft license: ", "").replace(" (dev)", "");
              return (
                <p key={v.id} className="text-xs text-gray-400">
                  <span className={v.severity === "critical" ? "text-red-400" : "text-yellow-400"}>
                    {lic}
                  </span>
                  {" — "}
                  <span className="text-gray-300">{pkg}</span>
                </p>
              );
            })}
            {licenseVulns.length > 5 && (
              <p className="text-xs text-gray-500">{"..."}{t("andMore", { count: licenseVulns.length - 5 })}</p>
            )}
          </div>
        </div>
      )}

      {/* SCA skipped banner */}
      {scaSkipped && (
        <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl px-4 py-3 flex items-center gap-3">
          <svg className="w-5 h-5 text-yellow-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
          </svg>
          <div>
            <p className="text-yellow-400 text-sm font-medium">{t("scaSkipped")}</p>
            <p className="text-gray-400 text-xs">{scaSkipped.message}</p>
          </div>
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
          {t("showExploitable", { count: exploitableCount })}
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
            placeholder={t("searchPlaceholder")}
            aria-label={t("searchPlaceholder")}
            className="w-full pl-9 pr-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-gray-700"
          />
        </div>

        {/* Severity filter */}
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-sm text-gray-300 focus:outline-none focus:border-gray-700"
        >
          <option value="all">{t("allSeverities")}</option>
          <option value="critical">{t("critical")}</option>
          <option value="warning">{t("warning")}</option>
          <option value="info">{t("info")}</option>
        </select>

        {/* File filter */}
        <select
          value={fileFilter}
          onChange={(e) => setFileFilter(e.target.value)}
          className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-sm text-gray-300 focus:outline-none focus:border-gray-700 max-w-48"
        >
          <option value="all">{t("allFiles")}</option>
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
          <option value="all">{t("allRules")}</option>
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

        {/* SBOM Download */}
        {depsJson && depsJson.length > 0 && (
          <button
            onClick={handleSbomDownload}
            className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-sm text-gray-300 hover:border-gray-700 hover:text-white transition-colors flex items-center gap-2 whitespace-nowrap"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
            </svg>
            SBOM
            <span className="px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-blue-500/15 text-blue-400">
              {depsJson.length}
            </span>
          </button>
        )}
      </div>

      {/* Result count */}
      <p className="text-gray-500 text-sm">
        {t("showing", { filtered: filtered.length, total: realVulns.length })}
      </p>

      {/* Results */}
      {filtered.length === 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center">
          <p className="text-gray-400">{t("noMatch")}</p>
        </div>
      )}

      {/* Empty SCA message */}
      {activeTab === "sca" && filteredSca.length === 0 && !scaSkipped && (
        <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-6 text-center">
          <p className="text-green-400 text-sm font-medium">{t("noDepVulns")}</p>
          <p className="text-gray-500 text-xs mt-1">{t("noDepVulnsDesc")}</p>
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
                {t("scaHeader", { count: filteredSca.length })}
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

            // Extract ecosystem from snippet: "[npm] ..." or "[PyPI] ..."
            const ecoMatch = pkgVulns[0]?.snippet?.match(/^\[([^\]]+)\]/);
            const ecosystem = ecoMatch?.[1] ?? null;

            // Extract fix version from suggestion (e.g. "Upgrade to 4.17.21 or later.")
            const fixVersions = [...new Set(pkgVulns.map((v) => {
              const m = v.suggestion?.match(/Upgrade to ([^\s]+) or later/);
              return m?.[1] ?? "";
            }).filter(Boolean))];

            return (
              <div
                key={pkgName}
                className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
              >
                <div className="px-4 py-3 border-b border-gray-800 bg-gray-900/50">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={maxSeverity} />
                      <span className="text-gray-200 text-sm font-medium">{pkgName}</span>
                      {ecosystem && (
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${
                          ecosystem === "npm" ? "bg-red-900/30 text-red-400 border-red-800" :
                          ecosystem === "PyPI" ? "bg-blue-900/30 text-blue-400 border-blue-800" :
                          ecosystem === "Go" ? "bg-cyan-900/30 text-cyan-400 border-cyan-800" :
                          ecosystem === "crates.io" ? "bg-orange-900/30 text-orange-400 border-orange-800" :
                          "bg-gray-800 text-gray-400 border-gray-700"
                        }`}>
                          {ecosystem}
                        </span>
                      )}
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
                      {pkgVulns.length > 1 ? t("cvesCount", { count: pkgVulns.length }) : t("cveCount", { count: pkgVulns.length })}
                    </span>
                  </div>
                  {fixVersions.length > 0 && (
                    <p className="text-green-400/80 text-xs mt-1.5 ml-7">
                      {t("fixAvailable", { pkg: pkgName, version: fixVersions[0] })}
                    </p>
                  )}
                  {depGraphJson && ecosystem && versions[0] && (
                    <div className="ml-7 mt-1">
                      <DepChain
                        graph={depGraphJson}
                        ecosystem={ecosystem}
                        name={pkgName}
                        version={versions[0]}
                      />
                    </div>
                  )}
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
                                <p className="text-xs text-gray-500 uppercase font-medium mb-1">{t("remediation")}</p>
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

                            {/* AI Explain for SCA */}
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
                {t("sastHeader", { count: filteredSast.length })}
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
                    {fileVulns.length > 1 ? t("issuesCount", { count: fileVulns.length }) : t("issueCount", { count: fileVulns.length })}
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
                              {t("lineCol", { line: v.line, col: v.column })}
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
                              <p className="text-xs text-gray-500 uppercase font-medium mb-1">{t("fixSuggestion")}</p>
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
