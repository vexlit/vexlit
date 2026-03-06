import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { NextResponse } from "next/server";
import Anthropic from "@anthropic-ai/sdk";

const anthropic = new Anthropic();

export async function POST(request: Request) {
  const supabase = await createSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  const { scanId } = body as { scanId: string };

  if (!scanId) {
    return NextResponse.json(
      { error: "scanId is required" },
      { status: 400 }
    );
  }

  const admin = createSupabaseAdmin();

  // Verify scan ownership
  const { data: scan } = await admin
    .from("scans")
    .select(
      "id, status, total_vulnerabilities, critical_count, warning_count, info_count, projects(name, user_id)"
    )
    .eq("id", scanId)
    .single();

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  if ((scan as any).projects?.user_id !== user.id) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  if (scan.status !== "completed") {
    return NextResponse.json(
      { error: "Scan is not completed" },
      { status: 400 }
    );
  }

  // Check cache
  const cacheKey = `report:${scanId}`;
  const { data: cached } = await admin
    .from("ai_cache")
    .select("response")
    .eq("cache_key", cacheKey)
    .single();

  if (cached) {
    return NextResponse.json({ report: cached.response, cached: true });
  }

  // Fetch vulnerabilities for this scan
  const { data: vulns } = await admin
    .from("vulnerabilities")
    .select("rule_name, severity, message, file_path, line, snippet, cwe")
    .eq("scan_id", scanId)
    .order("severity")
    .limit(100);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const projectName = (scan as any).projects?.name ?? "Unknown";

  const vulnSummary = (vulns ?? [])
    .map(
      (v, i) =>
        `${i + 1}. [${v.severity}] ${v.rule_name} — ${v.file_path}:${v.line}\n   ${v.message}${v.snippet ? `\n   Code: ${v.snippet.slice(0, 100)}` : ""}`
    )
    .join("\n");

  const prompt = `You are a senior security engineer. Generate a comprehensive security report for this code scan.

Project: ${projectName}
Total Vulnerabilities: ${scan.total_vulnerabilities}
- Critical: ${scan.critical_count}
- Warning: ${scan.warning_count}
- Info: ${scan.info_count}

Vulnerability Details:
${vulnSummary || "No vulnerabilities found."}

Write a security report in Korean with markdown formatting:

# 보안 분석 리포트: ${projectName}

## 1. 요약 (Executive Summary)
Overall risk assessment and key findings.

## 2. 취약점 패턴 분석
Group vulnerabilities by pattern/category. Identify recurring issues.

## 3. 우선순위 권장사항
Ranked list of what to fix first and why.

## 4. 아키텍처 레벨 보안 평가
High-level security posture assessment and recommendations.

Keep the report professional and actionable.`;

  try {
    const response = await anthropic.messages.create({
      model: "claude-sonnet-4-20250514",
      max_tokens: 4096,
      messages: [{ role: "user", content: prompt }],
    });

    const report =
      response.content[0].type === "text" ? response.content[0].text : "";

    await admin.from("ai_cache").upsert({
      cache_key: cacheKey,
      response: report,
    });

    return NextResponse.json({ report, cached: false });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
