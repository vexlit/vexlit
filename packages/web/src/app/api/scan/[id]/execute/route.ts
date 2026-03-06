import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { decrypt } from "@/lib/crypto";
import { fetchRepoTree, fetchFileContentsBatch } from "@/lib/github";
import { NextResponse } from "next/server";

// Process files in chunks to stay within serverless timeout
const CHUNK_SIZE = 10;
// Fetch files from GitHub in batches per execute call
const GITHUB_FETCH_BATCH = 40;

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
  const supabase = await createSupabaseServer();
  const {
    data: { session },
  } = await supabase.auth.getSession();

  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const admin = createSupabaseAdmin();

  // Get scan with file contents and verify ownership
  const { data: scan } = await admin
    .from("scans")
    .select(
      "id, status, file_contents, github_meta, project_id, projects(user_id)"
    )
    .eq("id", id)
    .single();

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  if ((scan as any).projects?.user_id !== session.user.id) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  // Skip if already completed or failed
  if (scan.status === "completed" || scan.status === "failed") {
    return NextResponse.json({ status: scan.status });
  }

  const startTime = Date.now();

  try {
    // ── Phase 1: GitHub file fetching (cursor-based) ──
    const githubMeta = scan.github_meta as GithubMeta | null;

    if (githubMeta) {
      // Try session provider_token first, fall back to stored token
      let providerToken = session.provider_token;
      if (!providerToken) {
        const { data: profile } = await admin
          .from("profiles")
          .select("github_access_token")
          .eq("id", session.user.id)
          .single();
        const encrypted = profile?.github_access_token;
        if (encrypted) {
          try { providerToken = decrypt(encrypted); } catch { providerToken = null; }
        }
      }

      if (!providerToken) {
        await admin
          .from("scans")
          .update({
            status: "failed",
            error_message: "GitHub token expired. Please re-login and retry.",
            github_meta: null,
          })
          .eq("id", id);
        return NextResponse.json({ status: "failed" });
      }

      // Atomic pending → running transition
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

      // First call: fetch tree, store all paths with cursor = 0
      if (!githubMeta.paths) {
        const paths = await fetchRepoTree(owner, repo, branch, providerToken);

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

        // Fetch first batch
        const batchPaths = paths.slice(0, GITHUB_FETCH_BATCH);
        const files = await fetchFileContentsBatch(
          owner,
          repo,
          branch,
          batchPaths,
          providerToken
        );

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
          remaining: done ? files.length : paths.length - nextCursor,
        });
      }

      // Subsequent calls: use cursor to fetch next batch
      const cursor = githubMeta.fetch_cursor ?? 0;
      const batchPaths = githubMeta.paths.slice(
        cursor,
        cursor + GITHUB_FETCH_BATCH
      );

      const files = await fetchFileContentsBatch(
        owner,
        repo,
        branch,
        batchPaths,
        providerToken
      );

      const existingFiles = (scan.file_contents ?? []) as {
        path: string;
        content: string;
      }[];
      const allFiles = [...existingFiles, ...files];
      const nextCursor = cursor + GITHUB_FETCH_BATCH;
      const done = nextCursor >= githubMeta.paths.length;

      await admin
        .from("scans")
        .update({
          file_contents: allFiles,
          github_meta: done
            ? null
            : {
                owner,
                repo,
                branch,
                paths: githubMeta.paths,
                fetch_cursor: nextCursor,
              },
        })
        .eq("id", id);

      return NextResponse.json({
        status: "running",
        phase: done ? "scanning" : "fetching",
        fetched: files.length,
        remaining: done
          ? allFiles.length
          : githubMeta.paths.length - nextCursor,
      });
    }

    // ── Phase 2: Scan processing (existing chunk logic) ──

    const files = (scan.file_contents ?? []) as {
      path: string;
      content: string;
    }[];

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
      return NextResponse.json({
        status: scan.status === "pending" ? "failed" : "completed",
      });
    }

    // Mark as running (only on first chunk) with atomic check
    const isFirstChunk = scan.status === "pending";
    if (isFirstChunk) {
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

    // Run SCA once on the first chunk (all files still available)
    if (isFirstChunk) {
      const scaVulns = await scaDependencies(files);
      if (scaVulns.length > 0) {
        await admin.from("vulnerabilities").insert(
          scaVulns.map((v) => ({
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
      }
    }

    const chunk = files.slice(0, CHUNK_SIZE);
    const remaining = files.slice(CHUNK_SIZE);

    const chunkVulnerabilities: {
      scan_id: string;
      rule_id: string;
      rule_name: string;
      severity: string;
      confidence: string;
      message: string;
      file_path: string;
      line: number;
      column: number;
      snippet: string | null;
      cwe: string | null;
      owasp: string | null;
      suggestion: string | null;
    }[] = [];

    const extMap: Record<string, "javascript" | "typescript" | "python"> = {
      ".js": "javascript",
      ".jsx": "javascript",
      ".mjs": "javascript",
      ".cjs": "javascript",
      ".ts": "typescript",
      ".tsx": "typescript",
      ".py": "python",
    };

    for (const file of chunk) {
      const ext = "." + file.path.split(".").pop()?.toLowerCase();
      const language = extMap[ext];
      if (!language) continue;

      const vulns = await engine.execute(file.path, file.content, language);

      for (const v of vulns) {
        chunkVulnerabilities.push({
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

    if (chunkVulnerabilities.length > 0) {
      await admin.from("vulnerabilities").insert(chunkVulnerabilities);
    }

    if (remaining.length > 0) {
      await admin
        .from("scans")
        .update({ file_contents: remaining })
        .eq("id", id);

      return NextResponse.json({
        status: "running",
        processed: chunk.length,
        remaining: remaining.length,
      });
    }

    // All files processed — finalize scan
    const { count: totalCount } = await admin
      .from("vulnerabilities")
      .select("*", { count: "exact", head: true })
      .eq("scan_id", id);

    const { data: severityCounts } = await admin
      .from("vulnerabilities")
      .select("severity")
      .eq("scan_id", id);

    let critical = 0,
      warning = 0,
      info = 0;
    for (const v of severityCounts ?? []) {
      if (v.severity === "critical") critical++;
      else if (v.severity === "warning") warning++;
      else info++;
    }

    await admin
      .from("scans")
      .update({
        status: "completed",
        total_vulnerabilities: totalCount ?? 0,
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
