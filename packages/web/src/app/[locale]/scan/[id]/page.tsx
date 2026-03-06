import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { PublicScanClient } from "@/components/public-scan-client";
import { notFound } from "next/navigation";
import { Link } from "@/i18n/navigation";
import type { Scan, Vulnerability } from "@/lib/types";

export default async function PublicScanPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const admin = createSupabaseAdmin();

  const { data: scan } = await admin
    .from("scans")
    .select("*, projects(name, github_url)")
    .eq("id", id)
    .single();

  if (!scan) notFound();

  const typedScan = scan as Scan & {
    projects: { name: string; github_url: string | null };
  };

  // For pending/running scans, show polling UI
  if (typedScan.status === "pending" || typedScan.status === "running") {
    return (
      <div className="min-h-screen bg-gray-950 text-white">
        <nav className="fixed top-0 w-full z-50 border-b border-gray-800 bg-gray-950/80 backdrop-blur-sm">
          <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
            <Link href="/" className="text-xl font-bold text-white">VEXLIT</Link>
            <Link href="/login" className="text-gray-400 hover:text-white text-sm transition-colors">
              Sign in
            </Link>
          </div>
        </nav>
        <div className="max-w-4xl mx-auto px-6 pt-24 pb-16">
          <div className="mb-6">
            <h1 className="text-2xl font-bold text-white">{typedScan.projects?.name ?? "Scan"}</h1>
            {typedScan.projects?.github_url && (
              <a
                href={typedScan.projects.github_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-500 hover:text-gray-300 text-sm mt-1 inline-flex items-center gap-1 transition-colors"
              >
                {typedScan.projects.github_url.replace("https://github.com/", "")}
              </a>
            )}
          </div>
          <PublicScanClient scanId={id} createdAt={typedScan.created_at} />
        </div>
      </div>
    );
  }

  // For completed/failed scans, show results
  const { data: vulnerabilities } = await admin
    .from("vulnerabilities")
    .select("*")
    .eq("scan_id", id)
    .order("severity", { ascending: true })
    .order("file_path", { ascending: true })
    .order("line", { ascending: true });

  const vulns = (vulnerabilities ?? []) as Vulnerability[];

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      <nav className="fixed top-0 w-full z-50 border-b border-gray-800 bg-gray-950/80 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
          <Link href="/" className="text-xl font-bold text-white">VEXLIT</Link>
          <div className="flex gap-4 items-center">
            <Link href="/login" className="text-gray-400 hover:text-white text-sm transition-colors">
              Sign in for full features
            </Link>
            <Link
              href="/login"
              className="px-4 py-2 bg-red-600 rounded-lg text-sm font-medium hover:bg-red-700 transition-colors"
            >
              Get Started
            </Link>
          </div>
        </div>
      </nav>

      <div className="max-w-4xl mx-auto px-6 pt-24 pb-16 space-y-6 animate-fade-in">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold text-white">{typedScan.projects?.name ?? "Scan Results"}</h1>
          {typedScan.projects?.github_url && (
            <a
              href={typedScan.projects.github_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-gray-500 hover:text-gray-300 text-sm mt-1 inline-flex items-center gap-1 transition-colors"
            >
              {typedScan.projects.github_url.replace("https://github.com/", "")}
            </a>
          )}
        </div>

        {/* Summary */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <SummaryCard label="Total" value={typedScan.total_vulnerabilities} />
          <SummaryCard label="Critical" value={typedScan.critical_count} color="text-red-400" />
          <SummaryCard label="Warning" value={typedScan.warning_count} color="text-yellow-400" />
          <SummaryCard label="Info" value={typedScan.info_count} color="text-blue-400" />
        </div>

        {/* Duration */}
        {typedScan.duration_ms && (
          <p className="text-gray-500 text-sm">
            Scanned in {(typedScan.duration_ms / 1000).toFixed(1)}s
          </p>
        )}

        {/* Failed */}
        {typedScan.status === "failed" && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4">
            <p className="text-red-400 text-sm">
              Scan failed: {typedScan.error_message ?? "Unknown error"}
            </p>
          </div>
        )}

        {/* Clean */}
        {typedScan.status === "completed" && vulns.length === 0 && (
          <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-8 text-center">
            <p className="text-green-400 text-lg font-medium">No vulnerabilities found</p>
            <p className="text-gray-500 text-sm mt-1">This repository looks clean.</p>
          </div>
        )}

        {/* Vulnerability list */}
        {vulns.length > 0 && (
          <div className="space-y-2">
            <h2 className="text-lg font-semibold text-white">
              Vulnerabilities ({vulns.length})
            </h2>
            {vulns.map((v, i) => (
              <div
                key={i}
                className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityDot severity={v.severity} />
                      <span className="text-white text-sm font-medium">{v.rule_name}</span>
                      <span className="text-gray-600 text-xs font-mono">{v.rule_id}</span>
                    </div>
                    <p className="text-gray-400 text-sm">{v.message}</p>
                    <p className="text-gray-600 text-xs mt-1">
                      {v.file_path}:{v.line}
                      {v.cwe && <span className="ml-2">{v.cwe}</span>}
                    </p>
                    {v.snippet && (
                      <pre className="mt-2 text-xs bg-gray-950 border border-gray-800 rounded px-3 py-2 overflow-x-auto text-gray-300">
                        {v.snippet}
                      </pre>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* CTA */}
        <div className="bg-gradient-to-br from-red-500/10 to-orange-500/10 border border-red-500/20 rounded-2xl p-6 text-center">
          <h3 className="text-lg font-semibold text-white mb-2">
            Want AI explanations, trend tracking, and more?
          </h3>
          <p className="text-gray-400 text-sm mb-4">
            Sign in to get AI-powered fix suggestions, scan history, and continuous monitoring.
          </p>
          <Link
            href="/login"
            className="inline-block px-6 py-2.5 bg-red-600 rounded-lg text-sm font-medium hover:bg-red-700 transition-colors"
          >
            Sign In Free
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
  const color: Record<string, string> = {
    critical: "bg-red-500",
    warning: "bg-yellow-500",
    info: "bg-blue-500",
  };
  return <span className={`w-2 h-2 rounded-full flex-shrink-0 ${color[severity] ?? "bg-gray-500"}`} />;
}
