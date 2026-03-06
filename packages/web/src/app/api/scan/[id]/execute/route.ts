import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { NextResponse } from "next/server";

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

  // Skip if already completed, failed, or already running
  if (scan.status === "completed" || scan.status === "failed") {
    return NextResponse.json({ status: scan.status });
  }

  if (scan.status === "running") {
    return NextResponse.json({ status: "running" });
  }

  const files = (scan.file_contents ?? []) as {
    path: string;
    content: string;
  }[];

  if (!files.length) {
    await admin
      .from("scans")
      .update({ status: "failed", error_message: "No files to scan" })
      .eq("id", id);
    return NextResponse.json({ status: "failed" });
  }

  const startTime = Date.now();

  try {
    // Mark as running
    await admin.from("scans").update({ status: "running" }).eq("id", id);

    const { RuleEngine } = await import("@vexlit/core");
    const engine = new RuleEngine();

    const allVulnerabilities: {
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

    for (const file of files) {
      const ext = "." + file.path.split(".").pop()?.toLowerCase();
      const language = extMap[ext];
      if (!language) continue;

      const vulns = engine.execute(file.path, file.content, language);

      for (const v of vulns) {
        allVulnerabilities.push({
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

    // Insert vulnerabilities
    if (allVulnerabilities.length > 0) {
      await admin.from("vulnerabilities").insert(allVulnerabilities);
    }

    // Count by severity
    let critical = 0,
      warning = 0,
      info = 0;
    for (const v of allVulnerabilities) {
      if (v.severity === "critical") critical++;
      else if (v.severity === "warning") warning++;
      else info++;
    }

    // Update scan as completed, clear file_contents to save space
    await admin
      .from("scans")
      .update({
        status: "completed",
        total_vulnerabilities: allVulnerabilities.length,
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
