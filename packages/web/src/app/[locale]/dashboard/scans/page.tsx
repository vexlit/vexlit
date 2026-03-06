import { createSupabaseServer } from "@/lib/supabase-server";
import { SeverityBadge } from "@/components/severity-badge";
import { Link } from "@/i18n/navigation";
import { DeleteButton } from "@/components/delete-button";
import { getTranslations } from "next-intl/server";
import type { Scan } from "@/lib/types";

export default async function ScansPage() {
  const t = await getTranslations("scans");
  const supabase = await createSupabaseServer();

  const { data: scans } = await supabase
    .from("scans")
    .select("*, projects(name)")
    .order("created_at", { ascending: false })
    .limit(50);

  const scanList = (scans ?? []) as (Scan & { projects: { name: string } })[];

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">{t("title")}</h1>
          <p className="text-gray-500 text-sm mt-1">
            {t("subtitle")}
          </p>
        </div>
        <Link
          href="/dashboard/new"
          className="px-4 py-2 bg-red-600 text-white rounded-lg text-sm font-medium hover:bg-red-700 transition-all hover:shadow-lg hover:shadow-red-600/20"
        >
          {t("newScan")}
        </Link>
      </div>

      {scanList.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center">
          <p className="text-gray-400">{t("noScans")}</p>
          <Link
            href="/dashboard/new"
            className="text-red-400 hover:text-red-300 text-sm mt-2 inline-block"
          >
            {t("startFirst")}
          </Link>
        </div>
      ) : (
        <>
          {/* Desktop table */}
          <div className="hidden sm:block bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left text-gray-400 text-xs font-medium px-4 py-3">{t("project")}</th>
                  <th className="text-left text-gray-400 text-xs font-medium px-4 py-3">{t("status")}</th>
                  <th className="text-left text-gray-400 text-xs font-medium px-4 py-3">{t("vulnerabilities")}</th>
                  <th className="text-left text-gray-400 text-xs font-medium px-4 py-3">{t("duration")}</th>
                  <th className="text-left text-gray-400 text-xs font-medium px-4 py-3">{t("date")}</th>
                  <th className="text-right text-gray-400 text-xs font-medium px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {scanList.map((scan) => (
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
                        {scan.total_vulnerabilities === 0 && scan.status === "completed" && <span className="text-green-400 text-xs">{t("clean")}</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-sm">
                      {scan.duration_ms ? `${(scan.duration_ms / 1000).toFixed(1)}s` : "-"}
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-sm">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <DeleteButton
                        endpoint={`/api/scan/${scan.id}`}
                        redirectTo="/dashboard/scans"
                        label={t("delete")}
                        confirmMessage={t("deleteConfirm")}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Mobile list */}
          <div className="sm:hidden bg-gray-900 border border-gray-800 rounded-xl overflow-hidden divide-y divide-gray-800">
            {scanList.map((scan) => (
              <div key={scan.id} className="px-4 py-3">
                <Link href={`/dashboard/scans/${scan.id}`} className="flex items-center justify-between">
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
                <div className="mt-2 flex justify-end">
                  <DeleteButton
                    endpoint={`/api/scan/${scan.id}`}
                    redirectTo="/dashboard/scans"
                    label={t("delete")}
                    confirmMessage={t("deleteConfirm")}
                  />
                </div>
              </div>
            ))}
          </div>
        </>
      )}
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
