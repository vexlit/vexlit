import { createSupabaseServer } from "@/lib/supabase-server";
import { SeverityBadge } from "@/components/severity-badge";
import { notFound } from "next/navigation";
import Link from "next/link";
import type { Scan } from "@/lib/types";

export default async function ProjectDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const supabase = await createSupabaseServer();

  const { data: project } = await supabase
    .from("projects")
    .select("*")
    .eq("id", id)
    .single();

  if (!project) notFound();

  const { data: scans } = await supabase
    .from("scans")
    .select("*")
    .eq("project_id", id)
    .order("created_at", { ascending: false });

  const scanList = (scans ?? []) as Scan[];

  // Trend: last 10 scans
  const completedScans = scanList
    .filter((s) => s.status === "completed")
    .slice(0, 10)
    .reverse();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Link
          href="/dashboard"
          className="text-gray-500 hover:text-gray-300 text-sm"
        >
          Dashboard
        </Link>
        <span className="text-gray-600 mx-2">/</span>
        <h1 className="text-2xl font-bold text-white inline">
          {project.name}
        </h1>
        {project.github_url && (
          <p className="text-gray-500 text-sm mt-1">{project.github_url}</p>
        )}
      </div>

      {/* Vulnerability Trend */}
      {completedScans.length > 1 && (
        <section className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h2 className="text-sm font-medium text-gray-400 mb-3">
            Vulnerability Trend (last {completedScans.length} scans)
          </h2>
          <div className="flex items-end gap-2 h-24">
            {completedScans.map((scan) => {
              const max = Math.max(
                ...completedScans.map((s) => s.total_vulnerabilities),
                1
              );
              const height = (scan.total_vulnerabilities / max) * 100;
              const barColor =
                scan.critical_count > 0
                  ? "bg-red-500"
                  : scan.warning_count > 0
                    ? "bg-yellow-500"
                    : scan.total_vulnerabilities > 0
                      ? "bg-blue-500"
                      : "bg-green-500";

              return (
                <Link
                  key={scan.id}
                  href={`/dashboard/scans/${scan.id}`}
                  className="flex-1 flex flex-col items-center gap-1"
                  title={`${scan.total_vulnerabilities} vulnerabilities`}
                >
                  <div
                    className={`w-full rounded-t ${barColor} transition-all hover:opacity-80`}
                    style={{
                      height: `${Math.max(height, 4)}%`,
                      minHeight: "2px",
                    }}
                  />
                  <span className="text-gray-600 text-[10px]">
                    {scan.total_vulnerabilities}
                  </span>
                </Link>
              );
            })}
          </div>
        </section>
      )}

      {/* Scan History */}
      <section>
        <h2 className="text-lg font-semibold text-white mb-4">Scan History</h2>
        {scanList.length === 0 ? (
          <p className="text-gray-400 text-sm">No scans yet for this project.</p>
        ) : (
          <div className="space-y-2">
            {scanList.map((scan) => (
              <Link
                key={scan.id}
                href={`/dashboard/scans/${scan.id}`}
                className="flex items-center justify-between bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 hover:border-gray-700 transition-colors"
              >
                <div className="flex items-center gap-4">
                  <StatusDot status={scan.status} />
                  <div>
                    <p className="text-white text-sm">
                      Scan{" "}
                      <span className="text-gray-500 font-mono text-xs">
                        {scan.id.slice(0, 8)}
                      </span>
                    </p>
                    <p className="text-gray-500 text-xs">
                      {new Date(scan.created_at).toLocaleString()}
                      {scan.duration_ms &&
                        ` · ${(scan.duration_ms / 1000).toFixed(1)}s`}
                    </p>
                  </div>
                </div>
                <div className="flex gap-2">
                  {scan.critical_count > 0 && (
                    <SeverityBadge
                      severity="critical"
                      count={scan.critical_count}
                    />
                  )}
                  {scan.warning_count > 0 && (
                    <SeverityBadge
                      severity="warning"
                      count={scan.warning_count}
                    />
                  )}
                  {scan.info_count > 0 && (
                    <SeverityBadge severity="info" count={scan.info_count} />
                  )}
                  {scan.total_vulnerabilities === 0 &&
                    scan.status === "completed" && (
                      <span className="text-green-400 text-xs">Clean</span>
                    )}
                </div>
              </Link>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function StatusDot({ status }: { status: string }) {
  const color: Record<string, string> = {
    pending: "bg-gray-500",
    running: "bg-blue-500 animate-pulse",
    completed: "bg-green-500",
    failed: "bg-red-500",
  };

  return (
    <div className={`w-2 h-2 rounded-full ${color[status] ?? color.pending}`} />
  );
}
