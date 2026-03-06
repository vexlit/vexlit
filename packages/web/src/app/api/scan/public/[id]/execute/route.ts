import { createSupabaseAdmin } from "@/lib/supabase-admin";
import {
  fetchPublicRepoTree,
  fetchPublicFilesBatch,
} from "@/lib/github-public";
import { NextResponse } from "next/server";

const CHUNK_SIZE = 10;
const GITHUB_FETCH_BATCH = 30;

interface GithubMeta {
  owner: string;
  repo: string;
  branch: string;
  paths?: string[];
  fetch_cursor?: number;
}

export async function POST(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const admin = createSupabaseAdmin();

  const { data: scan } = await admin
    .from("scans")
    .select("id, status, file_contents, github_meta, project_id")
    .eq("id", id)
    .single();

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  if (scan.status === "completed" || scan.status === "failed") {
    return NextResponse.json({ status: scan.status });
  }

  const startTime = Date.now();

  try {
    // ── Phase 1: GitHub file fetching ──
    const githubMeta = scan.github_meta as GithubMeta | null;

    if (githubMeta) {
      if (scan.status === "pending") {
        const { data: updated } = await admin
          .from("scans")
          .update({ status: "running" })
          .eq("id", id)
          .eq("status", "pending")
          .select("id");
        if (!updated || updated.length === 0) {
          return NextResponse.json({ status: "running" });
        }
      }

      const { owner, repo, branch } = githubMeta;

      // First call: fetch tree
      if (!githubMeta.paths) {
        const paths = await fetchPublicRepoTree(owner, repo, branch);

        if (!paths.length) {
          await admin
            .from("scans")
            .update({
              status: "failed",
              error_message: "No scannable files found in this repository",
              github_meta: null,
              completed_at: new Date().toISOString(),
            })
            .eq("id", id);
          return NextResponse.json({ status: "failed" });
        }

        const batchPaths = paths.slice(0, GITHUB_FETCH_BATCH);
        const files = await fetchPublicFilesBatch(owner, repo, branch, batchPaths);

        const nextCursor = Math.min(GITHUB_FETCH_BATCH, paths.length);
        const done = nextCursor >= paths.length;

        await admin
          .from("scans")
          .update({
            file_contents: files,
            github_meta: done
              ? null
              : { owner, repo, branch, paths, fetch_cursor: nextCursor },
          })
          .eq("id", id);

        return NextResponse.json({
          status: "running",
          phase: done ? "scanning" : "fetching",
          fetched: files.length,
          total: paths.length,
          remaining: done ? files.length : paths.length - nextCursor,
        });
      }

      // Subsequent calls: fetch next batch
      const cursor = githubMeta.fetch_cursor ?? 0;
      const batchPaths = githubMeta.paths.slice(cursor, cursor + GITHUB_FETCH_BATCH);

      const files = await fetchPublicFilesBatch(owner, repo, branch, batchPaths);
      const existingFiles = (scan.file_contents ?? []) as { path: string; content: string }[];
      const allFiles = [...existingFiles, ...files];
      const nextCursor = cursor + GITHUB_FETCH_BATCH;
      const done = nextCursor >= githubMeta.paths.length;

      await admin
        .from("scans")
        .update({
          file_contents: allFiles,
          github_meta: done
            ? null
            : { owner, repo, branch, paths: githubMeta.paths, fetch_cursor: nextCursor },
        })
        .eq("id", id);

      return NextResponse.json({
        status: "running",
        phase: done ? "scanning" : "fetching",
        fetched: files.length,
        total: githubMeta.paths.length,
        remaining: done ? allFiles.length : githubMeta.paths.length - nextCursor,
      });
    }

    // ── Phase 2: Scan processing ──
    const files = (scan.file_contents ?? []) as { path: string; content: string }[];

    if (!files.length) {
      await admin
        .from("scans")
        .update({
          status: scan.status === "pending" ? "failed" : "completed",
          error_message: scan.status === "pending" ? "No files to scan" : null,
          file_contents: null,
          completed_at: new Date().toISOString(),
        })
        .eq("id", id);
      return NextResponse.json({ status: scan.status === "pending" ? "failed" : "completed" });
    }

    if (scan.status === "pending") {
      const { data: updated } = await admin
        .from("scans")
        .update({ status: "running" })
        .eq("id", id)
        .eq("status", "pending")
        .select("id");
      if (!updated || updated.length === 0) {
        return NextResponse.json({ status: "running" });
      }
    }

    const { RuleEngine, scaDependencies } = await import("@vexlit/core");
    const engine = new RuleEngine();

    // Run SCA once when all files are still available (before chunking removes them)
    const isFirstScanChunk = scan.status !== "running";
    if (isFirstScanChunk) {
      const scaResult = await scaDependencies(files);
      if (scaResult.vulnerabilities.length > 0) {
        await admin.from("vulnerabilities").insert(
          scaResult.vulnerabilities.map((v) => ({
            scan_id: id,
            rule_id: v.ruleId,
            rule_name: v.ruleName,
            severity: v.severity,
            confidence: v.confidence ?? "high",
            message: v.message,
            file_path: v.filePath,
            line: v.line,
            column: v.column,
            snippet: v.snippet ?? null,
            cwe: v.cwe ?? null,
            owasp: v.owasp ?? null,
            suggestion: v.suggestion ?? null,
          }))
        );
      } else if (scaResult.skipped && scaResult.depCount > 0) {
        await admin.from("vulnerabilities").insert({
          scan_id: id,
          rule_id: "SCA-SKIPPED",
          rule_name: "SCA skipped",
          severity: "info",
          confidence: "low",
          message: `SCA analysis was skipped because the vulnerability database was unreachable. ${scaResult.depCount} dependencies were not checked.`,
          file_path: "-",
          line: 0,
          column: 1,
          snippet: null, cwe: null, owasp: null,
          suggestion: "Re-run the scan to retry SCA analysis.",
        });
      }
    }

    const chunk = files.slice(0, CHUNK_SIZE);
    const remaining = files.slice(CHUNK_SIZE);

    const extMap: Record<string, "javascript" | "typescript" | "python"> = {
      ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
      ".ts": "typescript", ".tsx": "typescript", ".py": "python",
    };

    const chunkVulns: {
      scan_id: string; rule_id: string; rule_name: string; severity: string;
      confidence: string; message: string; file_path: string; line: number;
      column: number; snippet: string | null; cwe: string | null;
      owasp: string | null; suggestion: string | null;
    }[] = [];

    for (const file of chunk) {
      const ext = "." + file.path.split(".").pop()?.toLowerCase();
      const language = extMap[ext];
      if (!language) continue;

      const vulns = await engine.execute(file.path, file.content, language);
      for (const v of vulns) {
        chunkVulns.push({
          scan_id: id,
          rule_id: v.ruleId,
          rule_name: v.ruleName,
          severity: v.severity,
          message: v.message,
          file_path: v.filePath,
          line: v.line,
          column: v.column,
          snippet: v.snippet ?? null,
          cwe: v.cwe ?? null,
          owasp: v.owasp ?? null,
          suggestion: v.suggestion ?? null,
          confidence: v.confidence ?? "medium",
        });
      }
    }

    if (chunkVulns.length > 0) {
      await admin.from("vulnerabilities").insert(chunkVulns);
    }

    if (remaining.length > 0) {
      await admin.from("scans").update({ file_contents: remaining }).eq("id", id);
      return NextResponse.json({
        status: "running",
        phase: "scanning",
        processed: chunk.length,
        remaining: remaining.length,
      });
    }

    // Finalize
    const { data: severityCounts } = await admin
      .from("vulnerabilities")
      .select("severity")
      .eq("scan_id", id);

    let critical = 0, warning = 0, info = 0;
    for (const v of severityCounts ?? []) {
      if (v.severity === "critical") critical++;
      else if (v.severity === "warning") warning++;
      else info++;
    }

    const total = critical + warning + info;

    await admin
      .from("scans")
      .update({
        status: "completed",
        total_vulnerabilities: total,
        critical_count: critical,
        warning_count: warning,
        info_count: info,
        duration_ms: Date.now() - startTime,
        completed_at: new Date().toISOString(),
        file_contents: null,
      })
      .eq("id", id);

    return NextResponse.json({ status: "completed" });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await admin
      .from("scans")
      .update({
        status: "failed",
        error_message: message,
        duration_ms: Date.now() - startTime,
        github_meta: null,
      })
      .eq("id", id);
    return NextResponse.json({ status: "failed" });
  }
}
