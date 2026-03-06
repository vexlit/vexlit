import { getUser } from "@/lib/auth";
import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { SeverityBadge } from "@/components/severity-badge";
import { LazyTrendChart as TrendChart } from "@/components/charts/lazy-trend-chart";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import type { Scan, Vulnerability } from "@/lib/types";

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
  const user = await getUser();
  const supabase = await createSupabaseServer();
  const admin = createSupabaseAdmin();
  const t = await getTranslations("dashboard");

  // Run all queries in parallel
  const [{ count: projectCount }, { data: recentScans }, { data: recentVulns }] =
    await Promise.all([
      supabase
        .from("projects")
        .select("*", { count: "exact", head: true })
        .eq("user_id", user!.id),
      supabase
        .from("scans")
        .select("*, projects(name)")
        .order("created_at", { ascending: false })
        .limit(10),
      admin
        .from("vulnerabilities")
        .select("*, scans!inner(project_id, projects!inner(name, user_id))")
        .order("created_at", { ascending: false })
        .limit(10),
    ]);

  // Filter to user's vulnerabilities
  const userVulns = ((recentVulns ?? []) as (Vulnerability & { scans: { project_id: string; projects: { name: string; user_id: string } } })[]).filter(
    (v) => v.scans?.projects?.user_id === user!.id
  );

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
          <h1 className="text-2xl font-bold text-white">{t("title")}</h1>
          <p className="text-gray-500 text-sm mt-1">{t("subtitle")}</p>
        </div>
        <Link
          href="/dashboard/new"
          className="px-4 py-2 bg-red-600 text-white rounded-lg text-sm font-medium hover:bg-red-700 transition-all hover:shadow-lg hover:shadow-red-600/20"
        >
          {t("newScan")}
        </Link>
      </div>

      {/* Security Overview Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <p className="text-gray-500 text-xs">{t("projects")}</p>
          <p className="text-2xl font-bold text-white mt-1">{projectCount ?? 0}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <p className="text-gray-500 text-xs">{t("activeVulnerabilities")}</p>
          <p className="text-2xl font-bold text-white mt-1">{totalVulns}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <p className="text-gray-500 text-xs">{t("critical")}</p>
          <p className="text-2xl font-bold text-red-400 mt-1">{totalCritical}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <p className="text-gray-500 text-xs">{t("warning")}</p>
          <p className="text-2xl font-bold text-yellow-400 mt-1">{totalWarning}</p>
        </div>
        <div className="col-span-2 lg:col-span-1 bg-gray-900 border border-gray-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-gray-500 text-xs">{t("securityScore")}</p>
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

      {/* Recent Vulnerabilities */}
      <section>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">{t("recentVulnerabilities")}</h2>
        </div>
        {userVulns.length === 0 ? (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center">
            <p className="text-gray-400 text-sm">{t("noVulnerabilities")}</p>
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
      </section>
    </div>
  );
}
