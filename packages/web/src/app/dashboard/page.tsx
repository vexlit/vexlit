import { createSupabaseServer } from "@/lib/supabase-server";
import { SeverityBadge } from "@/components/severity-badge";
import Link from "next/link";
import type { Project, Scan } from "@/lib/types";

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

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <Link
          href="/dashboard/new"
          className="px-4 py-2 bg-red-600 text-white rounded-lg text-sm font-medium hover:bg-red-700 transition-colors"
        >
          New Scan
        </Link>
      </div>

      {/* Projects */}
      <section>
        <h2 className="text-lg font-semibold text-white mb-4">Projects</h2>
        {!projects || projects.length === 0 ? (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
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
            {(projects as Project[]).map((project) => (
              <Link
                key={project.id}
                href={`/dashboard/projects/${project.id}`}
                className="bg-gray-900 border border-gray-800 rounded-lg p-4 hover:border-gray-700 transition-colors"
              >
                <h3 className="text-white font-medium">{project.name}</h3>
                {project.github_url && (
                  <p className="text-gray-500 text-sm mt-1 truncate">
                    {project.github_url}
                  </p>
                )}
                <p className="text-gray-600 text-xs mt-2">
                  {new Date(project.created_at).toLocaleDateString()}
                </p>
              </Link>
            ))}
          </div>
        )}
      </section>

      {/* Recent Scans */}
      <section>
        <h2 className="text-lg font-semibold text-white mb-4">Recent Scans</h2>
        {!recentScans || recentScans.length === 0 ? (
          <p className="text-gray-400 text-sm">No scans yet.</p>
        ) : (
          <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left text-gray-400 text-xs font-medium px-4 py-3">
                    Project
                  </th>
                  <th className="text-left text-gray-400 text-xs font-medium px-4 py-3">
                    Status
                  </th>
                  <th className="text-left text-gray-400 text-xs font-medium px-4 py-3">
                    Vulnerabilities
                  </th>
                  <th className="text-left text-gray-400 text-xs font-medium px-4 py-3">
                    Date
                  </th>
                </tr>
              </thead>
              <tbody>
                {(recentScans as (Scan & { projects: { name: string } })[]).map(
                  (scan) => (
                    <tr
                      key={scan.id}
                      className="border-b border-gray-800 last:border-0"
                    >
                      <td className="px-4 py-3">
                        <Link
                          href={`/dashboard/scans/${scan.id}`}
                          className="text-white text-sm hover:text-red-400"
                        >
                          {scan.projects?.name ?? "Unknown"}
                        </Link>
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={scan.status} />
                      </td>
                      <td className="px-4 py-3">
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
                            <SeverityBadge
                              severity="info"
                              count={scan.info_count}
                            />
                          )}
                          {scan.total_vulnerabilities === 0 &&
                            scan.status === "completed" && (
                              <span className="text-green-400 text-xs">
                                Clean
                              </span>
                            )}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-gray-500 text-sm">
                        {new Date(scan.created_at).toLocaleDateString()}
                      </td>
                    </tr>
                  )
                )}
              </tbody>
            </table>
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
    <span
      className={`px-2 py-0.5 rounded text-xs font-medium ${styles[status] ?? styles.pending}`}
    >
      {status}
    </span>
  );
}
