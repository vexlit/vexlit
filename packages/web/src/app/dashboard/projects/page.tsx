import { createSupabaseServer } from "@/lib/supabase-server";
import { SeverityBadge } from "@/components/severity-badge";
import { LazySeverityDonut as SeverityDonut } from "@/components/charts/lazy-severity-donut";
import Link from "next/link";
import type { Project, Scan } from "@/lib/types";

export default async function ProjectsPage() {
  const supabase = await createSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const [{ data: projects }, { data: recentScans }] = await Promise.all([
    supabase
      .from("projects")
      .select("*")
      .eq("user_id", user!.id)
      .order("updated_at", { ascending: false }),
    supabase
      .from("scans")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(50),
  ]);

  // Build per-project latest completed scan map
  const projectScans = new Map<string, Scan>();
  for (const scan of (recentScans ?? []) as Scan[]) {
    if (!projectScans.has(scan.project_id) && scan.status === "completed") {
      projectScans.set(scan.project_id, scan);
    }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Projects</h1>
          <p className="text-gray-500 text-sm mt-1">
            {(projects ?? []).length} project{(projects ?? []).length !== 1 ? "s" : ""} registered
          </p>
        </div>
        <Link
          href="/dashboard/new"
          className="px-4 py-2 bg-red-600 text-white rounded-lg text-sm font-medium hover:bg-red-700 transition-all hover:shadow-lg hover:shadow-red-600/20"
        >
          New Scan
        </Link>
      </div>

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
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
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
    </div>
  );
}
