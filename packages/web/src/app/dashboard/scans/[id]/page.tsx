import { createSupabaseServer } from "@/lib/supabase-server";
import { ScanPolling } from "@/components/scan-polling";
import { AiReportButton } from "@/components/ai-report-button";
import { ScanResultsClient } from "@/components/scan-results-client";
import { LazySeverityDonut as SeverityDonut } from "@/components/charts/lazy-severity-donut";
import { notFound } from "next/navigation";
import Link from "next/link";
import { DeleteButton } from "@/components/delete-button";
import type { Scan, Vulnerability } from "@/lib/types";

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const supabase = await createSupabaseServer();

  const { data: scan } = await supabase
    .from("scans")
    .select("*, projects(name, github_url)")
    .eq("id", id)
    .single();

  if (!scan) notFound();

  const { data: vulnerabilities } = await supabase
    .from("vulnerabilities")
    .select("*")
    .eq("scan_id", id)
    .order("severity", { ascending: true })
    .order("file_path", { ascending: true })
    .order("line", { ascending: true });

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
              Dashboard
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
            {typedScan.projects?.name ?? "Scan Results"}
          </h1>
        </div>
        <div className="flex items-center gap-3">
          <StatusPill status={typedScan.status} />
          <DeleteButton
            endpoint={`/api/scan/${id}`}
            redirectTo={`/dashboard/projects/${typedScan.project_id}`}
            label="Delete Scan"
            confirmMessage="Delete this scan and its results?"
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
            <p className="text-gray-500 text-xs">Total</p>
            <p className="text-xl font-bold text-white">
              {typedScan.total_vulnerabilities}
            </p>
          </div>
        </div>
        <SummaryCard
          label="Critical"
          value={typedScan.critical_count}
          color="text-red-400"
        />
        <SummaryCard
          label="Warning"
          value={typedScan.warning_count}
          color="text-yellow-400"
        />
        <SummaryCard
          label="Info"
          value={typedScan.info_count}
          color="text-blue-400"
        />
        <SummaryCard
          label="Duration"
          value={
            typedScan.duration_ms
              ? `${(typedScan.duration_ms / 1000).toFixed(1)}s`
              : "-"
          }
        />
        <SummaryCard
          label="Files"
          value={new Set(vulns.map((v) => v.file_path)).size || "-"}
        />
      </div>

      {/* Metadata */}
      {typedScan.commit_sha && (
        <p className="text-gray-500 text-sm">
          Commit:{" "}
          <code className="text-gray-400 bg-gray-900 px-1.5 py-0.5 rounded text-xs">
            {typedScan.commit_sha.slice(0, 7)}
          </code>
        </p>
      )}

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
            Scan failed: {typedScan.error_message ?? "Unknown error"}
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
            No vulnerabilities found
          </p>
          <p className="text-gray-500 text-sm mt-1">Your code looks clean!</p>
        </div>
      )}

      {/* Results with filtering */}
      {typedScan.status === "completed" && vulns.length > 0 && (
        <ScanResultsClient
          scanId={id}
          vulns={vulns}
          sarifJson={typedScan.sarif_json}
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
