import { createSupabaseAdmin } from "@/lib/supabase-admin";
import {
  fetchPublicDefaultBranch,
  fetchPublicFilesBatch,
} from "@/lib/github-public";
import { NextResponse } from "next/server";
import { createHmac } from "crypto";

/**
 * GitHub App webhook handler for PR Security Check.
 * Listens for `pull_request` events (opened, synchronize).
 * Scans the PR's head branch and posts results as a PR comment.
 *
 * Required env vars:
 *   GITHUB_WEBHOOK_SECRET — webhook secret for signature verification
 *   GITHUB_APP_TOKEN — GitHub App installation token (or GITHUB_TOKEN)
 */
export async function POST(request: Request) {
  const body = await request.text();

  // Verify webhook signature
  const signature = request.headers.get("x-hub-signature-256");
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (secret && signature) {
    const expected = "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
    if (signature !== expected) {
      return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
    }
  }

  const event = request.headers.get("x-github-event");
  if (event !== "pull_request") {
    return NextResponse.json({ ok: true, skipped: true });
  }

  const payload = JSON.parse(body);
  const action = payload.action;

  // Only handle opened and synchronize (new commits pushed)
  if (action !== "opened" && action !== "synchronize") {
    return NextResponse.json({ ok: true, skipped: true });
  }

  const pr = payload.pull_request;
  const repo = payload.repository;
  const owner = repo.owner.login;
  const repoName = repo.name;
  const headBranch = pr.head.ref;
  const prNumber = pr.number;

  const admin = createSupabaseAdmin();

  // Find matching project in our database
  const githubUrl = `https://github.com/${owner}/${repoName}`;
  const { data: project } = await admin
    .from("projects")
    .select("id, user_id, name")
    .eq("github_url", githubUrl)
    .single();

  if (!project) {
    // Not a tracked project — skip
    return NextResponse.json({ ok: true, skipped: true, reason: "project not found" });
  }

  // Check if user has PR check enabled
  const { data: profile } = await admin
    .from("profiles")
    .select("feature_pr_check")
    .eq("id", project.user_id)
    .single();

  if (!profile?.feature_pr_check) {
    return NextResponse.json({ ok: true, skipped: true, reason: "feature disabled" });
  }

  try {
    const token = process.env.GITHUB_APP_TOKEN || process.env.GITHUB_TOKEN;

    // Fetch only changed files from the PR
    const branch = headBranch || await fetchPublicDefaultBranch(owner, repoName);
    const changedPaths = await fetchPRChangedFiles(owner, repoName, prNumber, token);

    if (!changedPaths.length) {
      return NextResponse.json({ ok: true, skipped: true, reason: "no scannable files" });
    }

    const files = await fetchPublicFilesBatch(owner, repoName, branch, changedPaths);

    // Create scan record
    const { data: scan } = await admin
      .from("scans")
      .insert({
        project_id: project.id,
        status: "running",
        branch,
        commit_sha: pr.head.sha,
      })
      .select("id")
      .single();

    if (!scan) {
      return NextResponse.json({ error: "Failed to create scan" }, { status: 500 });
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
      })
      .eq("id", scan.id);

    // Post or update PR comment
    if (token) {
      const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://vexlit.com";
      const reportUrl = `${appUrl}/dashboard/scans/${scan.id}`;

      let commentBody: string;
      const marker = "<!-- VEXLIT-SCAN -->\n";
      if (allVulns.length === 0) {
        commentBody = `${marker}## VEXLIT Security Report\n\nNo vulnerabilities found. Your code looks clean!\n\n[View Full Report](${reportUrl})`;
      } else {
        const criticalList = allVulns
          .filter((v) => v.severity === "critical")
          .slice(0, 5)
          .map((v) => `- **${v.rule_name}** in \`${v.file_path}:${v.line}\``)
          .join("\n");

        const warningList = allVulns
          .filter((v) => v.severity === "warning")
          .slice(0, 5)
          .map((v) => `- ${v.rule_name} in \`${v.file_path}:${v.line}\``)
          .join("\n");

        commentBody = `${marker}## VEXLIT Security Report\n\n`;
        commentBody += `**${allVulns.length} vulnerabilities** found (${critical} critical, ${warning} warning, ${info} info)\n\n`;

        if (criticalList) {
          commentBody += `### Critical\n${criticalList}\n\n`;
        }
        if (warningList) {
          commentBody += `### Warning\n${warningList}\n\n`;
        }
        if (allVulns.length > 10) {
          commentBody += `*...and ${allVulns.length - 10} more*\n\n`;
        }

        commentBody += `[View Full Report](${reportUrl})`;
      }

      // Find existing VEXLIT comment to update instead of creating a new one
      const existingCommentId = await findExistingComment(owner, repoName, prNumber, token);

      if (existingCommentId) {
        await fetch(
          `https://api.github.com/repos/${owner}/${repoName}/issues/comments/${existingCommentId}`,
          {
            method: "PATCH",
            headers: {
              Authorization: `Bearer ${token}`,
              Accept: "application/vnd.github+json",
              "X-GitHub-Api-Version": "2022-11-28",
            },
            body: JSON.stringify({ body: commentBody }),
          }
        );
      } else {
        await fetch(
          `https://api.github.com/repos/${owner}/${repoName}/issues/${prNumber}/comments`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${token}`,
              Accept: "application/vnd.github+json",
              "X-GitHub-Api-Version": "2022-11-28",
            },
            body: JSON.stringify({ body: commentBody }),
          }
        );
      }
    }

    // Create notification
    await admin.from("notifications").insert({
      user_id: project.user_id,
      type: "pr_scan",
      title: `PR #${prNumber} scanned: ${project.name}`,
      message: allVulns.length > 0
        ? `Found ${allVulns.length} vulnerabilities (${critical} critical)`
        : "No vulnerabilities found",
      link: `/dashboard/scans/${scan.id}`,
    });

    return NextResponse.json({ ok: true, scanId: scan.id, vulnerabilities: allVulns.length });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 500 }
    );
  }
}

const SCANNABLE_EXTS = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py"]);

/** Fetch only changed file paths from a PR */
async function fetchPRChangedFiles(
  owner: string,
  repo: string,
  prNumber: number,
  token: string | undefined
): Promise<string[]> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}/files?per_page=100`,
    { headers }
  );

  if (!res.ok) return [];

  const files = (await res.json()) as { filename: string; status: string }[];
  return files
    .filter((f) => f.status !== "removed")
    .map((f) => f.filename)
    .filter((p) => {
      const ext = "." + p.split(".").pop()?.toLowerCase();
      return SCANNABLE_EXTS.has(ext);
    });
}

/** Find existing VEXLIT comment on a PR to update instead of creating a new one */
async function findExistingComment(
  owner: string,
  repo: string,
  prNumber: number,
  token: string
): Promise<number | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/issues/${prNumber}/comments?per_page=100`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    }
  );

  if (!res.ok) return null;

  const comments = (await res.json()) as { id: number; body: string }[];
  const existing = comments.find((c) => c.body.includes("<!-- VEXLIT-SCAN -->"));
  return existing?.id ?? null;
}
