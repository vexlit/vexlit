import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { NextResponse } from "next/server";

// Process files in chunks to stay within serverless timeout
const CHUNK_SIZE = 10;

export async function POST(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const supabase = await createSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const admin = createSupabaseAdmin();

  // Get scan with file contents and verify ownership
  const { data: scan } = await admin
    .from("scans")
    .select("id, status, file_contents, project_id, projects(user_id)")
    .eq("id", id)
    .single();

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  if ((scan as any).projects?.user_id !== user.id) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  // Skip if already completed or failed
  if (scan.status === "completed" || scan.status === "failed") {
    return NextResponse.json({ status: scan.status });
  }

  // Allow re-entry for "running" status — this enables chunk continuation
  // The client calls execute repeatedly; each call processes the next chunk

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

  const startTime = Date.now();

  try {
    // Mark as running (only on first chunk) with atomic check to prevent race condition
    if (scan.status === "pending") {
      const { data: updated } = await admin
        .from("scans")
        .update({ status: "running" })
        .eq("id", id)
        .eq("status", "pending")
        .select("id");

      // Another request already started processing
      if (!updated || updated.length === 0) {
        return NextResponse.json({ status: "running" });
      }
    }

    const { RuleEngine } = await import("@vexlit/core");
    const engine = new RuleEngine();

    // Take only a chunk of files to process within timeout
    const chunk = files.slice(0, CHUNK_SIZE);
    const remaining = files.slice(CHUNK_SIZE);

    const chunkVulnerabilities: {
      scan_id: string;
      rule_id: string;
      rule_name: string;
      severity: string;
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

      const vulns = engine.execute(file.path, file.content, language);

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
        });
      }
    }

    // Insert this chunk's vulnerabilities
    if (chunkVulnerabilities.length > 0) {
      await admin.from("vulnerabilities").insert(chunkVulnerabilities);
    }

    if (remaining.length > 0) {
      // More files to process — update remaining files, keep status as running
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
    // Count all vulnerabilities for this scan
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
      })
      .eq("id", id);
    return NextResponse.json({ status: "failed" });
  }
}
