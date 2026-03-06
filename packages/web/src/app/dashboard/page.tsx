import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { SeverityBadge } from "@/components/severity-badge";
import { LazySeverityDonut as SeverityDonut } from "@/components/charts/lazy-severity-donut";
import { LazyTrendChart as TrendChart } from "@/components/charts/lazy-trend-chart";
import Link from "next/link";
import type { Project, Scan, Vulnerability } from "@/lib/types";

function computeSecurityScore(criticals: number, warnings: number): { score: number; grade: string; color: string } {
  const score = Math.max(0, 100 - criticals * 10 - warnings * 3);
  let grade: string;
  let color: string;
  if (score >= 90) { grade = "A"; color = "text-green-400"; }
  else if (score >= 80) { grade = "B"; color = "text-green-400"; }
  else if (score >= 70) { grade = "C"; color = "text-yellow-400"; }
  else if (score >= 60) { grade = "D"; color = "text-orange-400"; }
  else { grade = "F"; color = "text-red-400"; }
  return { score, grade, color };
}

export default async function DashboardPage() {
  const supabase = await createSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const { data: projects } = await supabase
    .from("projects")
    .select("*")
    .eq("user_id", user!.id)
    .order("updated_at", { ascending: false });

  const { data: recentScans } = await supabase
    .from("scans")
    .select("*, projects(name)")
    .order("created_at", { ascending: false })
    .limit(10);

  // Fetch recent vulnerabilities for timeline
  const admin = createSupabaseAdmin();
  const { data: recentVulns } = await admin
    .from("vulnerabilities")
    .select("*, scans!inner(project_id, projects!inner(name, user_id))")
    .order("created_at", { ascending: false })
    .limit(10);

  // Filter to user's vulnerabilities
  const userVulns = (recentVulns ?? []).filter(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (v: any) => v.scans?.projects?.user_id === user!.id
  ) as (Vulnerability & { scans: { project_id: string; projects: { name: string } } })[];

  // Build per-project latest scan map
  const projectScans = new Map<string, Scan>();
  for (const scan of (recentScans ?? []) as (Scan & { projects: { name: string } })[]) {
    if (!projectScans.has(scan.project_id) && scan.status === "completed") {
      projectScans.set(scan.project_id, scan);
    }
  }

  // Aggregate stats
  let totalCritical = 0;
  let totalWarning = 0;
  let totalInfo = 0;
  for (const scan of projectScans.values()) {
    totalCritical += scan.critical_count;
    totalWarning += scan.warning_count;
    totalInfo += scan.info_count;
  }
  const totalVulns = totalCritical + totalWarning + totalInfo;
  const { grade, color } = computeSecurityScore(totalCritical, totalWarning);

  // Trend data
  const completedScans = ((recentScans ?? []) as Scan[])
    .filter((s) => s.status === "completed")
    .reverse();

  const trendData = completedScans.map((s) => ({
    date: new Date(s.created_at).toLocaleDateString("en", { month: "short", day: "numeric" }),
    critical: s.critical_count,
    warning: s.warning_count,
    info: s.info_count,
    total: s.total_vulnerabilities,
  }));

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-gray-500 text-sm mt-1">
            Security overview across all projects
          </p>
        </div>
        <Link
          href="/dashboard/new"
          className="px-4 py-2 bg-red-600 text-white rounded-lg text-sm font-medium hover:bg-red-700 transition-all hover:shadow-lg hover:shadow-red-600/20"
        >
          New Scan
        </Link>
      </div>

      {/* Security Overview Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <p className="text-gray-500 text-xs">Projects</p>
          <p className="text-2xl font-bold text-white mt-1">{(projects ?? []).length}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <p className="text-gray-500 text-xs">Active Vulnerabilities</p>
          <p className="text-2xl font-bold text-white mt-1">{totalVulns}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <p className="text-gray-500 text-xs">Critical</p>
          <p className="text-2xl font-bold text-red-400 mt-1">{totalCritical}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <p className="text-gray-500 text-xs">Warning</p>
          <p className="text-2xl font-bold text-yellow-400 mt-1">{totalWarning}</p>
        </div>
        <div className="col-span-2 lg:col-span-1 bg-gray-900 border border-gray-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-gray-500 text-xs">Security Score</p>
            <p className={`text-3xl font-bold mt-1 ${color}`}>{grade}</p>
          </div>
          <div className={`w-12 h-12 rounded-full border-4 ${
            grade === "A" || grade === "B" ? "border-green-500/40" :
            grade === "C" ? "border-yellow-500/40" :
            "border-red-500/40"
          } flex items-center justify-center`}>
            <span className={`text-sm font-bold ${color}`}>{grade}</span>
          </div>
        </div>
      </div>

      {/* Trend Chart */}
      {trendData.length > 1 && <TrendChart data={trendData} />}

      {/* Two column: Timeline + Quick Actions */}
      <div className="grid lg:grid-cols-3 gap-6">
        {/* Vulnerability Timeline */}
        <div className="lg:col-span-2">
          <h2 className="text-lg font-semibold text-white mb-4">Recent Vulnerabilities</h2>
          {userVulns.length === 0 ? (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center">
              <p className="text-gray-400 text-sm">No vulnerabilities found yet</p>
            </div>
          ) : (
            <div className="bg-gray-900 border border-gray-800 rounded-xl divide-y divide-gray-800">
              {userVulns.slice(0, 8).map((v) => (
                <Link
                  key={v.id}
                  href={`/dashboard/scans/${v.scan_id}`}
                  className="flex items-start gap-3 px-4 py-3 hover:bg-gray-800/30 transition-colors"
                >
                  <span className={`mt-0.5 w-2 h-2 rounded-full shrink-0 ${
                    v.severity === "critical" ? "bg-red-500" :
                    v.severity === "warning" ? "bg-yellow-500" : "bg-blue-500"
                  }`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-white text-sm font-medium truncate">{v.rule_name}</span>
                      <SeverityBadge severity={v.severity} />
                    </div>
                    <p className="text-gray-500 text-xs mt-0.5 truncate">
                      {v.file_path}:{v.line} — {v.scans?.projects?.name}
                    </p>
                  </div>
                  <span className="text-gray-600 text-xs whitespace-nowrap">
                    {new Date(v.created_at).toLocaleTimeString("en", { hour: "2-digit", minute: "2-digit" })}
                  </span>
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* Quick Actions */}
        <div>
          <h2 className="text-lg font-semibold text-white mb-4">Quick Actions</h2>
          <div className="space-y-3">
            <Link
              href="/dashboard/new"
              className="flex items-center gap-3 bg-gray-900 border border-gray-800 rounded-xl p-4 hover:border-gray-700 transition-all"
            >
              <div className="w-9 h-9 rounded-lg bg-red-500/10 flex items-center justify-center">
                <svg className="w-4 h-4 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
                </svg>
              </div>
              <div>
                <p className="text-white text-sm font-medium">New Scan</p>
                <p className="text-gray-500 text-xs">Scan a new repository</p>
              </div>
            </Link>
            <Link
              href="/dashboard/settings"
              className="flex items-center gap-3 bg-gray-900 border border-gray-800 rounded-xl p-4 hover:border-gray-700 transition-all"
            >
              <div className="w-9 h-9 rounded-lg bg-gray-500/10 flex items-center justify-center">
                <svg className="w-4 h-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
              </div>
              <div>
                <p className="text-white text-sm font-medium">Settings</p>
                <p className="text-gray-500 text-xs">Manage preferences</p>
              </div>
            </Link>
          </div>
        </div>
      </div>

      {/* Projects */}
      <section>
        <h2 className="text-lg font-semibold text-white mb-4">Projects</h2>
        {!projects || projects.length === 0 ? (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center">
            <div className="w-12 h-12 rounded-full bg-gray-800 flex items-center justify-center mx-auto mb-3">
              <svg className="w-6 h-6 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 10.5v6m3-3H9m4.06-7.19l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
              </svg>
            </div>
            <p className="text-gray-400">No projects yet.</p>
            <Link
              href="/dashboard/new"
              className="text-red-400 hover:text-red-300 text-sm mt-2 inline-block"
            >
              Create your first scan
            </Link>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {(projects as Project[]).map((project) => {
              const latestScan = projectScans.get(project.id);
              const health = !latestScan ? "gray" :
                latestScan.critical_count > 0 ? "red" :
                latestScan.warning_count > 0 ? "yellow" : "green";
              return (
                <Link
                  key={project.id}
                  href={`/dashboard/projects/${project.id}`}
                  className="bg-gray-900 border border-gray-800 rounded-xl p-4 hover:border-gray-700 transition-all group"
                >
                  <div className="flex items-start justify-between">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${
                          health === "green" ? "bg-green-500" :
                          health === "yellow" ? "bg-yellow-500" :
                          health === "red" ? "bg-red-500" : "bg-gray-600"
                        }`} />
                        <h3 className="text-white font-medium truncate group-hover:text-red-400 transition-colors">
                          {project.name}
                        </h3>
                      </div>
                      {project.github_url && (
                        <p className="text-gray-500 text-xs mt-0.5 truncate pl-4">
                          {project.github_url.replace("https://github.com/", "")}
                        </p>
                      )}
                    </div>
                    {latestScan && (
                      <SeverityDonut
                        critical={latestScan.critical_count}
                        warning={latestScan.warning_count}
                        info={latestScan.info_count}
                        size={48}
                      />
                    )}
                  </div>

                  {latestScan ? (
                    <div className="mt-3 pt-3 border-t border-gray-800 flex items-center gap-2">
                      <div className="flex gap-1.5 flex-1">
                        {latestScan.critical_count > 0 && (
                          <SeverityBadge severity="critical" count={latestScan.critical_count} />
                        )}
                        {latestScan.warning_count > 0 && (
                          <SeverityBadge severity="warning" count={latestScan.warning_count} />
                        )}
                        {latestScan.info_count > 0 && (
                          <SeverityBadge severity="info" count={latestScan.info_count} />
                        )}
                        {latestScan.total_vulnerabilities === 0 && (
                          <span className="text-green-400 text-xs font-medium">Clean</span>
                        )}
                      </div>
                      <span className="text-gray-600 text-xs">
                        {new Date(latestScan.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  ) : (
                    <div className="mt-3 pt-3 border-t border-gray-800">
                      <span className="text-gray-600 text-xs">No completed scans</span>
                    </div>
                  )}
                </Link>
              );
            })}
          </div>
        )}
      </section>

      {/* Recent Scans */}
      <section>
        <h2 className="text-lg font-semibold text-white mb-4">Recent Scans</h2>
        {!recentScans || recentScans.length === 0 ? (
          <p className="text-gray-400 text-sm">No scans yet.</p>
        ) : (
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            {/* Desktop table */}
            <div className="hidden sm:block">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-800">
                    <th className="text-left text-gray-400 text-xs font-medium px-4 py-3">Project</th>
                    <th className="text-left text-gray-400 text-xs font-medium px-4 py-3">Status</th>
                    <th className="text-left text-gray-400 text-xs font-medium px-4 py-3">Vulnerabilities</th>
                    <th className="text-left text-gray-400 text-xs font-medium px-4 py-3">Duration</th>
                    <th className="text-left text-gray-400 text-xs font-medium px-4 py-3">Date</th>
                  </tr>
                </thead>
                <tbody>
                  {(recentScans as (Scan & { projects: { name: string } })[]).map((scan) => (
                    <tr key={scan.id} className="border-b border-gray-800 last:border-0 hover:bg-gray-800/30 transition-colors">
                      <td className="px-4 py-3">
                        <Link href={`/dashboard/scans/${scan.id}`} className="text-white text-sm hover:text-red-400 transition-colors">
                          {scan.projects?.name ?? "Unknown"}
                        </Link>
                      </td>
                      <td className="px-4 py-3"><StatusBadge status={scan.status} /></td>
                      <td className="px-4 py-3">
                        <div className="flex gap-1.5">
                          {scan.critical_count > 0 && <SeverityBadge severity="critical" count={scan.critical_count} />}
                          {scan.warning_count > 0 && <SeverityBadge severity="warning" count={scan.warning_count} />}
                          {scan.info_count > 0 && <SeverityBadge severity="info" count={scan.info_count} />}
                          {scan.total_vulnerabilities === 0 && scan.status === "completed" && <span className="text-green-400 text-xs">Clean</span>}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-gray-500 text-sm">
                        {scan.duration_ms ? `${(scan.duration_ms / 1000).toFixed(1)}s` : "-"}
                      </td>
                      <td className="px-4 py-3 text-gray-500 text-sm">
                        {new Date(scan.created_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile list */}
            <div className="sm:hidden divide-y divide-gray-800">
              {(recentScans as (Scan & { projects: { name: string } })[]).map((scan) => (
                <Link key={scan.id} href={`/dashboard/scans/${scan.id}`} className="flex items-center justify-between px-4 py-3">
                  <div>
                    <p className="text-white text-sm">{scan.projects?.name ?? "Unknown"}</p>
                    <div className="flex items-center gap-2 mt-1">
                      <StatusBadge status={scan.status} />
                      <span className="text-gray-600 text-xs">{new Date(scan.created_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                  <div className="flex gap-1.5">
                    {scan.critical_count > 0 && <SeverityBadge severity="critical" count={scan.critical_count} />}
                    {scan.warning_count > 0 && <SeverityBadge severity="warning" count={scan.warning_count} />}
                  </div>
                </Link>
              ))}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    pending: "bg-gray-500/10 text-gray-400",
    running: "bg-blue-500/10 text-blue-400",
    completed: "bg-green-500/10 text-green-400",
    failed: "bg-red-500/10 text-red-400",
  };

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${styles[status] ?? styles.pending}`}>
      {status}
    </span>
  );
}
