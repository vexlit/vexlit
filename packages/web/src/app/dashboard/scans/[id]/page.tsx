import { createSupabaseServer } from "@/lib/supabase-server";
import { SeverityBadge } from "@/components/severity-badge";
import { ScanPolling } from "@/components/scan-polling";
import { AiExplainButton } from "@/components/ai-explain-button";
import { AiFixButton } from "@/components/ai-fix-button";
import { AiReportButton } from "@/components/ai-report-button";
import { notFound } from "next/navigation";
import Link from "next/link";
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

  // Group by file
  const fileGroups = new Map<string, Vulnerability[]>();
  for (const v of vulns) {
    const existing = fileGroups.get(v.file_path) ?? [];
    existing.push(v);
    fileGroups.set(v.file_path, existing);
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Link
            href="/dashboard"
            className="text-gray-500 hover:text-gray-300 text-sm"
          >
            Dashboard
          </Link>
          <span className="text-gray-600 mx-2">/</span>
          <h1 className="text-2xl font-bold text-white inline">
            {typedScan.projects?.name}
          </h1>
        </div>
        <StatusPill status={typedScan.status} />
      </div>

      {/* Summary */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <SummaryCard label="Total" value={typedScan.total_vulnerabilities} />
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
      </div>

      {/* Scan metadata */}
      {typedScan.commit_sha && (
        <p className="text-gray-500 text-sm">
          Commit: <code className="text-gray-400">{typedScan.commit_sha}</code>
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
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
          <p className="text-red-400 text-sm">
            Scan failed: {typedScan.error_message ?? "Unknown error"}
          </p>
        </div>
      )}

      {/* Results by file */}
      {typedScan.status === "completed" && vulns.length === 0 && (
        <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-8 text-center">
          <p className="text-green-400 text-lg font-medium">
            No vulnerabilities found
          </p>
          <p className="text-gray-500 text-sm mt-1">Your code looks clean!</p>
        </div>
      )}

      {Array.from(fileGroups.entries()).map(([filePath, fileVulns]) => (
        <div
          key={filePath}
          className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden"
        >
          <div className="px-4 py-3 border-b border-gray-800 bg-gray-900/50">
            <span className="text-gray-300 text-sm font-mono">{filePath}</span>
            <span className="text-gray-600 text-xs ml-2">
              {fileVulns.length} issue{fileVulns.length > 1 ? "s" : ""}
            </span>
          </div>

          <div className="divide-y divide-gray-800">
            {fileVulns.map((v) => (
              <div key={v.id} className="px-4 py-4">
                <div className="flex items-start gap-3">
                  <SeverityBadge severity={v.severity} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-white text-sm font-medium">
                        {v.rule_name}
                      </span>
                      <span className="text-gray-600 text-xs">
                        Line {v.line}:{v.column}
                      </span>
                    </div>
                    <p className="text-gray-400 text-sm mt-1">{v.message}</p>

                    {/* Code snippet */}
                    {v.snippet && (
                      <pre className="mt-2 px-3 py-2 bg-gray-950 rounded text-sm font-mono text-gray-300 overflow-x-auto">
                        <span className="text-gray-600 select-none">
                          {v.line} |{" "}
                        </span>
                        {v.snippet}
                      </pre>
                    )}

                    {/* Fix suggestion */}
                    {v.suggestion && (
                      <p className="mt-2 text-sm text-green-400/80">
                        Fix: {v.suggestion}
                      </p>
                    )}

                    {/* CWE / OWASP */}
                    <div className="flex gap-3 mt-2">
                      {v.cwe && (
                        <span className="text-gray-600 text-xs">{v.cwe}</span>
                      )}
                      {v.owasp && (
                        <span className="text-gray-600 text-xs">
                          {v.owasp}
                        </span>
                      )}
                    </div>

                    {/* AI Actions */}
                    <div className="flex gap-2 mt-3">
                      <AiExplainButton
                        scanId={id}
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
                        scanId={id}
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
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
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
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <p className="text-gray-500 text-xs">{label}</p>
      <p className={`text-2xl font-bold ${color ?? "text-white"} mt-1`}>
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

