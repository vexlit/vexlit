import { createSupabaseServer } from "@/lib/supabase-server";
import { ScanPolling } from "@/components/scan-polling";
import { AiReportButton } from "@/components/ai-report-button";
import { ScanResultsClient } from "@/components/scan-results-client";
import { LazySeverityDonut as SeverityDonut } from "@/components/charts/lazy-severity-donut";
import { notFound } from "next/navigation";
import { Link } from "@/i18n/navigation";
import { DeleteButton } from "@/components/delete-button";
import { getTranslations } from "next-intl/server";
import type { Scan, Vulnerability } from "@/lib/types";

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const t = await getTranslations("scanDetail");
  const supabase = await createSupabaseServer();

  const [{ data: scan }, { data: vulnerabilities }] = await Promise.all([
    supabase
      .from("scans")
      .select("*, projects(name, github_url)")
      .eq("id", id)
      .single(),
    supabase
      .from("vulnerabilities")
      .select("*")
      .eq("scan_id", id)
      .order("severity", { ascending: true })
      .order("file_path", { ascending: true })
      .order("line", { ascending: true }),
  ]);

  if (!scan) notFound();

  const typedScan = scan as Scan & {
    projects: { name: string; github_url: string | null };
  };
  const vulns = (vulnerabilities ?? []) as Vulnerability[];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-sm">
            <Link
              href="/dashboard"
              className="text-gray-500 hover:text-gray-300 transition-colors"
            >
              {t("dashboard")}
            </Link>
            <span className="text-gray-600">/</span>
            {typedScan.projects && (
              <>
                <Link
                  href={`/dashboard/projects/${typedScan.project_id}`}
                  className="text-gray-500 hover:text-gray-300 transition-colors"
                >
                  {typedScan.projects.name}
                </Link>
                <span className="text-gray-600">/</span>
              </>
            )}
            <span className="text-gray-400 font-mono">{id.slice(0, 8)}</span>
          </div>
          <h1 className="text-2xl font-bold text-white mt-1">
            {typedScan.projects?.name ?? t("scanResults")}
          </h1>
        </div>
        <div className="flex items-center gap-3">
          <StatusPill status={typedScan.status} />
          <DeleteButton
            endpoint={`/api/scan/${id}`}
            redirectTo={`/dashboard/projects/${typedScan.project_id}`}
            label={t("deleteScan")}
            confirmMessage={t("deleteScanConfirm")}
          />
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 flex items-center gap-3 col-span-2 md:col-span-1">
          <SeverityDonut
            critical={typedScan.critical_count}
            warning={typedScan.warning_count}
            info={typedScan.info_count}
            size={48}
          />
          <div>
            <p className="text-gray-500 text-xs">{t("total")}</p>
            <p className="text-xl font-bold text-white">
              {typedScan.total_vulnerabilities}
            </p>
          </div>
        </div>
        <SummaryCard
          label={t("critical")}
          value={typedScan.critical_count}
          color="text-red-400"
        />
        <SummaryCard
          label={t("warning")}
          value={typedScan.warning_count}
          color="text-yellow-400"
        />
        <SummaryCard
          label={t("info")}
          value={typedScan.info_count}
          color="text-blue-400"
        />
        <SummaryCard
          label={t("duration")}
          value={
            typedScan.duration_ms
              ? `${(typedScan.duration_ms / 1000).toFixed(1)}s`
              : "-"
          }
        />
        <SummaryCard
          label={t("files")}
          value={new Set(vulns.map((v) => v.file_path)).size || "-"}
        />
      </div>

      {/* Metadata */}
      {typedScan.commit_sha && (
        <p className="text-gray-500 text-sm">
          {t("commit")}:{" "}
          <code className="text-gray-400 bg-gray-900 px-1.5 py-0.5 rounded text-xs">
            {typedScan.commit_sha.slice(0, 7)}
          </code>
        </p>
      )}

      {/* Policy status banner */}
      {typedScan.policy_status === "violated" && (
        <div className="bg-orange-500/10 border border-orange-500/20 rounded-xl p-4 flex items-center gap-3">
          <svg className="w-5 h-5 text-orange-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
          </svg>
          <p className="text-orange-400 text-sm font-medium">{t("policyViolated")}</p>
        </div>
      )}
      {typedScan.policy_status === "passed" && (
        <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-4 flex items-center gap-3">
          <svg className="w-5 h-5 text-green-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-green-400 text-sm font-medium">{t("policyPassed")}</p>
        </div>
      )}

      {/* Fix priority list */}
      {typedScan.status === "completed" && (() => {
        const priority = vulns.filter(
          (v) => v.severity === "critical" || (v.severity === "warning" && v.confidence === "high")
        ).slice(0, 5);
        if (priority.length === 0) return null;
        return (
          <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-5">
            <div className="flex items-center gap-2 mb-1">
              <svg className="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
              </svg>
              <h3 className="text-red-400 font-semibold text-sm">
                {t("fixPriorityTitle", { count: priority.length })}
              </h3>
            </div>
            <p className="text-gray-500 text-xs mb-3">{t("fixPriorityDesc")}</p>
            <ul className="space-y-2">
              {priority.map((v) => (
                <li key={v.id} className="flex items-start gap-3 bg-gray-900/60 rounded-lg px-3 py-2.5">
                  <span className={`mt-0.5 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 ${
                    v.severity === "critical"
                      ? "bg-red-500/20 text-red-400"
                      : "bg-yellow-500/20 text-yellow-400"
                  }`}>
                    {v.severity === "critical" ? t("critical") : t("warning")}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-white text-sm font-medium truncate">{v.rule_name}</p>
                    {v.suggestion && (
                      <p className="text-green-400/70 text-xs mt-0.5 truncate">
                        Fix: {v.suggestion}
                      </p>
                    )}
                    <p className="text-gray-500 text-xs truncate mt-0.5">
                      {v.file_path}:{v.line} {v.cwe ? `· ${v.cwe}` : ""}
                    </p>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        );
      })()}

      {/* AI Report button */}
      {typedScan.status === "completed" && vulns.length > 0 && (
        <AiReportButton scanId={id} />
      )}

      {/* Pending/Running state */}
      {(typedScan.status === "pending" || typedScan.status === "running") && (
        <ScanPolling scanId={id} createdAt={typedScan.created_at} />
      )}

      {/* Failed state */}
      {typedScan.status === "failed" && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4">
          <p className="text-red-400 text-sm">
            {t("scanFailed", { error: typedScan.error_message ?? "Unknown error" })}
          </p>
        </div>
      )}

      {/* Clean scan */}
      {typedScan.status === "completed" && vulns.length === 0 && (
        <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-8 text-center">
          <svg className="w-12 h-12 text-green-500 mx-auto mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-green-400 text-lg font-medium">
            {t("noVulns")}
          </p>
          <p className="text-gray-500 text-sm mt-1">{t("codeLooksClean")}</p>
        </div>
      )}

      {/* Results with filtering */}
      {typedScan.status === "completed" && vulns.length > 0 && (
        <ScanResultsClient
          scanId={id}
          vulns={vulns}
          sarifJson={typedScan.sarif_json}
          depsJson={typedScan.deps_json as import("@/components/scan-results-client").DepEntry[] | null}
          depGraphJson={typedScan.dep_graph_json as import("@/components/scan-results-client").DepGraphData | null}
          projectName={typedScan.projects?.name}
        />
      )}
    </div>
  );
}

function SummaryCard({
  label,
  value,
  color,
}: {
  label: string;
  value: number | string;
  color?: string;
}) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <p className="text-gray-500 text-xs">{label}</p>
      <p className={`text-xl font-bold ${color ?? "text-white"} mt-1`}>
        {value}
      </p>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const styles: Record<string, string> = {
    pending: "bg-gray-800 text-gray-400",
    running: "bg-blue-900/50 text-blue-400",
    completed: "bg-green-900/50 text-green-400",
    failed: "bg-red-900/50 text-red-400",
  };

  return (
    <span
      className={`px-3 py-1 rounded-full text-sm font-medium ${styles[status] ?? styles.pending}`}
    >
      {status}
    </span>
  );
}
