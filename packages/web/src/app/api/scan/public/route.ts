import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { fetchPublicDefaultBranch } from "@/lib/github-public";
import { NextResponse } from "next/server";

// Anonymous user ID for public scans
const ANON_USER_ID = "00000000-0000-0000-0000-000000000000";

// Simple rate limiter: max 10 public scans per minute per IP
const rateMap = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = rateMap.get(ip);
  if (!entry || now > entry.resetAt) {
    rateMap.set(ip, { count: 1, resetAt: now + 60_000 });
    return true;
  }
  if (entry.count >= 10) return false;
  entry.count++;
  return true;
}

export async function POST(request: Request) {
  // Rate limiting
  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  if (!checkRateLimit(ip)) {
    return NextResponse.json(
      { error: "Too many requests. Please wait a moment." },
      { status: 429 }
    );
  }

  const body = await request.json();
  const { url } = body as { url?: string };

  if (!url?.trim()) {
    return NextResponse.json({ error: "GitHub URL is required" }, { status: 400 });
  }

  // Parse owner/repo from URL
  const match = url.trim().match(/github\.com\/([^/\s]+)\/([^/\s#?]+)/);
  if (!match) {
    return NextResponse.json(
      { error: "Invalid GitHub URL. Use: https://github.com/owner/repo" },
      { status: 400 }
    );
  }

  const owner = match[1];
  const repo = match[2].replace(/\.git$/, "");
  const projectName = `${owner}/${repo}`;
  const githubUrl = `https://github.com/${owner}/${repo}`;

  try {
    // Fetch default branch (also verifies repo exists and is public)
    const branch = await fetchPublicDefaultBranch(owner, repo);

    const admin = createSupabaseAdmin();

    // Find or create anonymous project
    let projectId: string;
    const { data: existing } = await admin
      .from("projects")
      .select("id")
      .eq("user_id", ANON_USER_ID)
      .eq("name", projectName)
      .single();

    if (existing) {
      projectId = existing.id;
      await admin
        .from("projects")
        .update({ updated_at: new Date().toISOString() })
        .eq("id", projectId);
    } else {
      const { data: newProject, error: projectError } = await admin
        .from("projects")
        .insert({ user_id: ANON_USER_ID, name: projectName, github_url: githubUrl })
        .select("id")
        .single();

      if (projectError || !newProject) {
        return NextResponse.json({ error: "Failed to create project" }, { status: 500 });
      }
      projectId = newProject.id;
    }

    // Create scan record with github metadata for deferred fetching
    const { data: scan, error: scanError } = await admin
      .from("scans")
      .insert({
        project_id: projectId,
        status: "pending",
        github_meta: { owner, repo, branch },
      })
      .select("id")
      .single();

    if (scanError || !scan) {
      return NextResponse.json({ error: "Failed to create scan" }, { status: 500 });
    }

    return NextResponse.json({ scanId: scan.id, owner, repo, branch });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to access repository";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
