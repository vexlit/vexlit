import { createSupabaseServer } from "@/lib/supabase-server";
import { SeverityBadge } from "@/components/severity-badge";
import { LazyTrendChart as TrendChart } from "@/components/charts/lazy-trend-chart";
import { QuickRescan } from "@/components/quick-rescan";
import { notFound } from "next/navigation";
import Link from "next/link";
import { DeleteButton } from "@/components/delete-button";
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

  const completedScans = scanList
    .filter((s) => s.status === "completed")
    .slice(0, 10)
    .reverse();

  const trendData = completedScans.map((s) => ({
    date: new Date(s.created_at).toLocaleDateString("en", {
      month: "short",
      day: "numeric",
    }),
    critical: s.critical_count,
    warning: s.warning_count,
    info: s.info_count,
    total: s.total_vulnerabilities,
  }));

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm">
            <Link
              href="/dashboard"
              className="text-gray-500 hover:text-gray-300 transition-colors"
            >
              Dashboard
            </Link>
            <span className="text-gray-600">/</span>
            <span className="text-gray-400">{project.name}</span>
          </div>
          <h1 className="text-2xl font-bold text-white mt-1">{project.name}</h1>
          {project.github_url && (
            <a
              href={project.github_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-gray-500 hover:text-gray-300 text-sm mt-1 inline-flex items-center gap-1 transition-colors"
            >
              {project.github_url.replace("https://github.com/", "")}
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
              </svg>
            </a>
          )}
        </div>
        <div className="flex items-center gap-3">
          <QuickRescan projectId={id} />
          <DeleteButton
            endpoint={`/api/projects/${id}`}
            redirectTo="/dashboard"
            label="Delete Project"
            confirmMessage="Delete this project and all scans?"
          />
        </div>
      </div>

      {/* Trend chart */}
      {trendData.length > 1 && <TrendChart data={trendData} />}

      {/* Scan History */}
      <section>
        <h2 className="text-lg font-semibold text-white mb-4">Scan History</h2>
        {scanList.length === 0 ? (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center">
            <p className="text-gray-400">No scans yet for this project.</p>
            <Link
              href="/dashboard/new"
              className="text-red-400 hover:text-red-300 text-sm mt-2 inline-block"
            >
              Start a scan
            </Link>
          </div>
        ) : (
          <div className="space-y-2">
            {scanList.map((scan) => (
              <Link
                key={scan.id}
                href={`/dashboard/scans/${scan.id}`}
                className="flex items-center justify-between bg-gray-900 border border-gray-800 rounded-xl px-4 py-3 hover:border-gray-700 transition-all group"
              >
                <div className="flex items-center gap-4">
                  <StatusDot status={scan.status} />
                  <div>
                    <p className="text-white text-sm group-hover:text-red-400 transition-colors">
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
                    <SeverityBadge severity="critical" count={scan.critical_count} />
                  )}
                  {scan.warning_count > 0 && (
                    <SeverityBadge severity="warning" count={scan.warning_count} />
                  )}
                  {scan.info_count > 0 && (
                    <SeverityBadge severity="info" count={scan.info_count} />
                  )}
                  {scan.total_vulnerabilities === 0 && scan.status === "completed" && (
                    <span className="text-green-400 text-xs font-medium">Clean</span>
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
    <div className={`w-2.5 h-2.5 rounded-full ${color[status] ?? color.pending}`} />
  );
}
