import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const supabase = await createSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const formData = await request.formData();
  const projectName = formData.get("projectName") as string;
  const githubUrl = (formData.get("githubUrl") as string) || null;
  const files = formData.getAll("files") as File[];

  if (!projectName?.trim()) {
    return NextResponse.json(
      { error: "Project name is required" },
      { status: 400 }
    );
  }

  if (!files.length && !githubUrl) {
    return NextResponse.json(
      { error: "Upload files or provide a GitHub URL" },
      { status: 400 }
    );
  }

  const admin = createSupabaseAdmin();

  // Create or find project
  let projectId: string;
  const { data: existingProject } = await admin
    .from("projects")
    .select("id")
    .eq("user_id", user.id)
    .eq("name", projectName.trim())
    .single();

  if (existingProject) {
    projectId = existingProject.id;
    await admin
      .from("projects")
      .update({ updated_at: new Date().toISOString(), github_url: githubUrl })
      .eq("id", projectId);
  } else {
    const { data: newProject, error: projectError } = await admin
      .from("projects")
      .insert({
        user_id: user.id,
        name: projectName.trim(),
        github_url: githubUrl,
      })
      .select("id")
      .single();

    if (projectError || !newProject) {
      return NextResponse.json(
        { error: "Failed to create project" },
        { status: 500 }
      );
    }
    projectId = newProject.id;
  }

  // Create scan record (pending)
  const { data: scan, error: scanError } = await admin
    .from("scans")
    .insert({ project_id: projectId, status: "pending" })
    .select("id")
    .single();

  if (scanError || !scan) {
    return NextResponse.json(
      { error: "Failed to create scan" },
      { status: 500 }
    );
  }

  // Collect file contents for scanning
  const fileContents: { path: string; content: string }[] = [];

  for (const file of files) {
    if (file.size > 0) {
      const text = await file.text();
      fileContents.push({ path: file.name, content: text });
    }
  }

  // Execute scan synchronously — fast enough for file uploads
  await executeScan(scan.id, fileContents, admin);

  return NextResponse.json({ scanId: scan.id });
}

async function executeScan(
  scanId: string,
  files: { path: string; content: string }[],
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  admin: any
) {
  const startTime = Date.now();

  try {
    // Mark as running
    await admin.from("scans").update({ status: "running" }).eq("id", scanId);

    // Dynamic import of @vexlit/core to keep it server-side only
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
          scan_id: scanId,
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

    const duration = Date.now() - startTime;

    // Update scan as completed
    await admin
      .from("scans")
      .update({
        status: "completed",
        total_vulnerabilities: allVulnerabilities.length,
        critical_count: critical,
        warning_count: warning,
        info_count: info,
        duration_ms: duration,
        completed_at: new Date().toISOString(),
      })
      .eq("id", scanId);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await admin
      .from("scans")
      .update({
        status: "failed",
        error_message: message,
        duration_ms: Date.now() - startTime,
      })
      .eq("id", scanId);
  }
}
