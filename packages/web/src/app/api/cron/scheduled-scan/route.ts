import { createSupabaseAdmin } from "@/lib/supabase-admin";
import {
  fetchPublicDefaultBranch,
  fetchPublicRepoTree,
  fetchPublicFilesBatch,
} from "@/lib/github-public";
import { NextResponse } from "next/server";

/**
 * Vercel Cron endpoint — runs scheduled scans for all eligible projects.
 * Triggered daily at 06:00 UTC via vercel.json cron config.
 * Protected by CRON_SECRET to prevent unauthorized access.
 */
export async function GET(request: Request) {
  // Verify cron secret
  const authHeader = request.headers.get("authorization");
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const admin = createSupabaseAdmin();

  // Find all projects with scheduled scans enabled
  const { data: projects, error: projectsError } = await admin
    .from("projects")
    .select("id, user_id, name, github_url, scan_schedule")
    .not("scan_schedule", "is", null)
    .neq("scan_schedule", "none");

  if (projectsError || !projects?.length) {
    return NextResponse.json({
      ok: true,
      scanned: 0,
      message: projectsError?.message ?? "No scheduled projects",
    });
  }

  // Filter by schedule: daily always runs, weekly only on Sundays
  const now = new Date();
  const dayOfWeek = now.getUTCDay(); // 0 = Sunday
  const eligible = projects.filter(
    (p) => p.scan_schedule === "daily" || (p.scan_schedule === "weekly" && dayOfWeek === 0)
  );

  if (!eligible.length) {
    return NextResponse.json({ ok: true, scanned: 0, message: "No projects due today" });
  }

  const results: { project: string; status: string; scanId?: string }[] = [];

  for (const project of eligible) {
    try {
      // Parse owner/repo from github_url
      const match = project.github_url?.match(/github\.com\/([^/]+)\/([^/\s#?]+)/);
      if (!match) {
        results.push({ project: project.name, status: "skipped: no github_url" });
        continue;
      }

      const owner = match[1];
      const repo = match[2].replace(/\.git$/, "");

      // Fetch branch + tree + files using GITHUB_TOKEN
      const branch = await fetchPublicDefaultBranch(owner, repo);
      const paths = await fetchPublicRepoTree(owner, repo, branch);

      if (!paths.length) {
        results.push({ project: project.name, status: "skipped: no scannable files" });
        continue;
      }

      const files = await fetchPublicFilesBatch(owner, repo, branch, paths);

      // Create scan record
      const { data: scan, error: scanError } = await admin
        .from("scans")
        .insert({
          project_id: project.id,
          status: "running",
          branch,
          file_contents: files,
        })
        .select("id")
        .single();

      if (scanError || !scan) {
        results.push({ project: project.name, status: `error: ${scanError?.message}` });
        continue;
      }

      // Run scan engine
      const { RuleEngine } = await import("@vexlit/core");
      const engine = new RuleEngine();
      const startTime = Date.now();

      const extMap: Record<string, "javascript" | "typescript" | "python"> = {
        ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        ".ts": "typescript", ".tsx": "typescript",
        ".py": "python",
      };

      const allVulns: {
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

      for (const file of files) {
        const ext = "." + file.path.split(".").pop()?.toLowerCase();
        const language = extMap[ext];
        if (!language) continue;

        const vulns = await engine.execute(file.path, file.content, language);
        for (const v of vulns) {
          allVulns.push({
            scan_id: scan.id,
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

      if (allVulns.length > 0) {
        await admin.from("vulnerabilities").insert(allVulns);
      }

      // Count by severity
      let critical = 0, warning = 0, info = 0;
      for (const v of allVulns) {
        if (v.severity === "critical") critical++;
        else if (v.severity === "warning") warning++;
        else info++;
      }

      // Finalize scan
      await admin
        .from("scans")
        .update({
          status: "completed",
          total_vulnerabilities: allVulns.length,
          critical_count: critical,
          warning_count: warning,
          info_count: info,
          duration_ms: Date.now() - startTime,
          completed_at: new Date().toISOString(),
          file_contents: null,
        })
        .eq("id", scan.id);

      // Create notification
      await admin.from("notifications").insert({
        user_id: project.user_id,
        type: "scheduled_scan",
        title: `Scheduled scan: ${project.name}`,
        message: allVulns.length > 0
          ? `Found ${allVulns.length} vulnerabilities (${critical} critical)`
          : "No vulnerabilities found",
        link: `/dashboard/scans/${scan.id}`,
      });

      // Send webhooks if configured
      await sendWebhooks(admin, project.user_id, project.name, scan.id, allVulns.length, critical, warning);

      results.push({ project: project.name, status: "completed", scanId: scan.id });
    } catch (err) {
      results.push({
        project: project.name,
        status: `error: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  return NextResponse.json({ ok: true, scanned: results.length, results });
}

/** Send Slack/Discord webhooks for scan completion */
async function sendWebhooks(
  admin: ReturnType<typeof createSupabaseAdmin>,
  userId: string,
  projectName: string,
  scanId: string,
  totalVulns: number,
  critical: number,
  warning: number
) {
  const { data: profile } = await admin
    .from("profiles")
    .select("slack_webhook_url, discord_webhook_url")
    .eq("id", userId)
    .single();

  if (!profile) return;

  const message = totalVulns > 0
    ? `VEXLIT Scan: ${projectName} — ${totalVulns} vulnerabilities found (${critical} critical, ${warning} warning)`
    : `VEXLIT Scan: ${projectName} — No vulnerabilities found`;

  const link = `${process.env.NEXT_PUBLIC_APP_URL ?? "https://vexlit.com"}/dashboard/scans/${scanId}`;

  // Slack webhook
  if (profile.slack_webhook_url) {
    try {
      await fetch(profile.slack_webhook_url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: message,
          blocks: [
            {
              type: "section",
              text: { type: "mrkdwn", text: `*${message}*\n<${link}|View Report>` },
            },
          ],
        }),
      });
    } catch {
      // Silently fail — don't break scan flow
    }
  }

  // Discord webhook
  if (profile.discord_webhook_url) {
    try {
      await fetch(profile.discord_webhook_url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: `**${message}**\n${link}`,
        }),
      });
    } catch {
      // Silently fail
    }
  }
}
