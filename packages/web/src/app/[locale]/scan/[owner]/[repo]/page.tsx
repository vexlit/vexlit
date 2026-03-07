import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { getTranslations } from "next-intl/server";
import { LandingNav } from "@/components/landing/landing-nav";
import { Link } from "@/i18n/navigation";
import type { Scan, Vulnerability } from "@/lib/types";
import { PublicScanClient } from "@/components/public-scan-client";
import { StartScanButton } from "@/components/start-scan-button";
import type { Metadata } from "next";

const ANON_USER_ID = "00000000-0000-0000-0000-000000000000";

interface PageProps {
  params: Promise<{ owner: string; repo: string }>;
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { owner, repo } = await params;
  return {
    title: `${owner}/${repo} Security Scan — VEXLIT`,
    description: `View security scan results for ${owner}/${repo}. SAST, SCA, and secret detection powered by VEXLIT.`,
    openGraph: {
      title: `${owner}/${repo} Security Scan — VEXLIT`,
      description: `View security scan results for ${owner}/${repo}. SAST, SCA, and secret detection powered by VEXLIT.`,
    },
  };
}

export default async function RepoScanPage({ params }: PageProps) {
  const { owner, repo } = await params;
  const admin = createSupabaseAdmin();
  const t = await getTranslations("publicScan");
  const tNav = await getTranslations("nav");
  const projectName = `${owner}/${repo}`;
  const githubUrl = `https://github.com/${owner}/${repo}`;

  // Find the project (anonymous or any user's)
  const { data: project } = await admin
    .from("projects")
    .select("id")
    .eq("name", projectName)
    .order("created_at", { ascending: false })
    .limit(1)
    .single();

  if (!project) {
    // No scan yet — show "start scan" page
    return (
      <div className="min-h-screen bg-gray-950 text-white">
        <LandingNav />
        <div className="max-w-4xl mx-auto px-6 pt-24 pb-16 text-center">
          <h1 className="text-2xl font-bold mb-2">{projectName}</h1>
          <a
            href={githubUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="text-gray-500 hover:text-gray-300 text-sm transition-colors"
          >
            {githubUrl}
          </a>
          <div className="mt-8 bg-gray-900 border border-gray-800 rounded-xl p-8">
            <p className="text-gray-400 mb-6">{t("noScanYet")}</p>
            <StartScanButton owner={owner} repo={repo} label={t("startScan")} />
          </div>
        </div>
      </div>
    );
  }

  // Find the latest completed scan
  const { data: latestScan } = await admin
    .from("scans")
    .select("*")
    .eq("project_id", project.id)
    .order("created_at", { ascending: false })
    .limit(1)
    .single();

  if (!latestScan) {
    return (
      <div className="min-h-screen bg-gray-950 text-white">
        <LandingNav />
        <div className="max-w-4xl mx-auto px-6 pt-24 pb-16 text-center">
          <h1 className="text-2xl font-bold mb-2">{projectName}</h1>
          <div className="mt-8 bg-gray-900 border border-gray-800 rounded-xl p-8">
            <p className="text-gray-400 mb-6">{t("noScanYet")}</p>
            <StartScanButton owner={owner} repo={repo} label={t("startScan")} />
          </div>
        </div>
      </div>
    );
  }

  const scan = latestScan as Scan;

  // If scan is still in progress, show polling UI
  if (scan.status === "pending" || scan.status === "running") {
    return (
      <div className="min-h-screen bg-gray-950 text-white">
        <LandingNav />
        <div className="max-w-4xl mx-auto px-6 pt-24 pb-16">
          <div className="mb-6">
            <h1 className="text-2xl font-bold text-white">{projectName}</h1>
            <a href={githubUrl} target="_blank" rel="noopener noreferrer" className="text-gray-500 hover:text-gray-300 text-sm transition-colors">
              {githubUrl.replace("https://github.com/", "")}
            </a>
          </div>
          <PublicScanClient scanId={scan.id} createdAt={scan.created_at} />
        </div>
      </div>
    );
  }

  // Completed scan — show results
  const { data: vulnerabilities } = await admin
    .from("vulnerabilities")
    .select("*")
    .eq("scan_id", scan.id)
    .order("severity", { ascending: true })
    .order("file_path", { ascending: true })
    .order("line", { ascending: true });

  const vulns = (vulnerabilities ?? []) as Vulnerability[];
  const realVulns = vulns.filter((v) => v.rule_id !== "SCA-META" && v.rule_id !== "SCA-SKIPPED");

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      <LandingNav />

      <div className="max-w-4xl mx-auto px-6 pt-24 pb-16 space-y-6 animate-fade-in">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">{projectName}</h1>
            <a href={githubUrl} target="_blank" rel="noopener noreferrer" className="text-gray-500 hover:text-gray-300 text-sm mt-1 inline-flex items-center gap-1 transition-colors">
              {githubUrl.replace("https://github.com/", "")}
            </a>
          </div>
          <StartScanButton owner={owner} repo={repo} label={t("rescan")} small />
        </div>

        {/* Summary */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <SummaryCard label="Total" value={scan.total_vulnerabilities} />
          <SummaryCard label="Critical" value={scan.critical_count} color="text-red-400" />
          <SummaryCard label="Warning" value={scan.warning_count} color="text-yellow-400" />
          <SummaryCard label="Info" value={scan.info_count} color="text-blue-400" />
        </div>

        {/* Duration & timestamp */}
        <div className="flex items-center gap-4 text-gray-500 text-sm">
          {scan.duration_ms && <span>{t("scannedIn", { time: (scan.duration_ms / 1000).toFixed(1) })}</span>}
          <span>{new Date(scan.created_at).toLocaleDateString()}</span>
        </div>

        {/* Share link */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 min-w-0">
            <svg className="w-4 h-4 text-gray-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m9.86-4.243a4.5 4.5 0 00-1.242-7.244l4.5-4.5a4.5 4.5 0 016.364 6.364l-1.757 1.757" />
            </svg>
            <code className="text-gray-400 text-xs font-mono truncate">
              vexlit.com/scan/{owner}/{repo}
            </code>
          </div>
          <span className="text-gray-600 text-xs flex-shrink-0">{t("shareableLink")}</span>
        </div>

        {/* Failed */}
        {scan.status === "failed" && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4">
            <p className="text-red-400 text-sm">{t("scanFailed", { error: scan.error_message ?? "Unknown error" })}</p>
          </div>
        )}

        {/* Clean */}
        {scan.status === "completed" && realVulns.length === 0 && (
          <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-8 text-center">
            <p className="text-green-400 text-lg font-medium">{t("noVulns")}</p>
            <p className="text-gray-500 text-sm mt-1">{t("repoClean")}</p>
          </div>
        )}

        {/* Vulnerability list */}
        {realVulns.length > 0 && (
          <div className="space-y-2">
            <h2 className="text-lg font-semibold text-white">{t("vulnCount", { count: realVulns.length })}</h2>
            {realVulns.map((v, i) => (
              <div key={i} className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityDot severity={v.severity} />
                  <span className="text-white text-sm font-medium">{v.rule_name}</span>
                  <span className="text-gray-600 text-xs font-mono">{v.rule_id}</span>
                </div>
                <p className="text-gray-400 text-sm">{v.message}</p>
                <p className="text-gray-600 text-xs mt-1">
                  {v.file_path}:{v.line}
                  {v.cwe && (
                    <a
                      href={`https://cwe.mitre.org/data/definitions/${v.cwe.replace("CWE-", "")}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="ml-2 text-blue-400 hover:underline"
                    >
                      {v.cwe}
                    </a>
                  )}
                </p>
                {v.suggestion && (
                  <p className="text-green-400/70 text-xs mt-1">Fix: {v.suggestion}</p>
                )}
              </div>
            ))}
          </div>
        )}

        {/* CTA */}
        <div className="bg-gradient-to-br from-red-500/10 to-orange-500/10 border border-red-500/20 rounded-2xl p-6 text-center">
          <h3 className="text-lg font-semibold text-white mb-2">{t("ctaTitle")}</h3>
          <p className="text-gray-400 text-sm mb-4">{t("ctaDesc")}</p>
          <Link href="/login" className="inline-block px-6 py-2.5 bg-red-600 rounded-lg text-sm font-medium hover:bg-red-700 transition-colors">
            {tNav("signInFree")}
          </Link>
        </div>
      </div>
    </div>
  );
}

function SummaryCard({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <p className="text-gray-500 text-xs">{label}</p>
      <p className={`text-xl font-bold ${color ?? "text-white"} mt-1`}>{value}</p>
    </div>
  );
}

function SeverityDot({ severity }: { severity: string }) {
  const color: Record<string, string> = { critical: "bg-red-500", warning: "bg-yellow-500", info: "bg-blue-500" };
  return <span className={`w-2 h-2 rounded-full flex-shrink-0 ${color[severity] ?? "bg-gray-500"}`} />;
}

