import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { fetchPublicDefaultBranch } from "@/lib/github-public";
import { NextResponse } from "next/server";

// Anonymous user ID for public scans
const ANON_USER_ID = "00000000-0000-0000-0000-000000000000";

// --- Rate limiting ---
// Per-minute burst limit + daily cap per IP.
// In-memory; resets on cold start — acceptable for serverless since
// Vercel spins down idle functions and each instance tracks its own window.
const BURST_LIMIT = 5; // max scans per minute per IP
const DAILY_LIMIT = 30; // max scans per day per IP

interface RateEntry {
  minuteCount: number;
  minuteResetAt: number;
  dailyCount: number;
  dailyResetAt: number;
}

const rateMap = new Map<string, RateEntry>();

// Periodically clean stale entries to prevent memory leak
let lastCleanup = Date.now();
function cleanupRateMap() {
  const now = Date.now();
  if (now - lastCleanup < 300_000) return; // every 5 min
  lastCleanup = now;
  for (const [key, entry] of rateMap) {
    if (now > entry.dailyResetAt) rateMap.delete(key);
  }
}

function checkRateLimit(ip: string): { allowed: boolean; retryAfter?: number } {
  cleanupRateMap();
  const now = Date.now();
  let entry = rateMap.get(ip);

  if (!entry || now > entry.dailyResetAt) {
    entry = {
      minuteCount: 1,
      minuteResetAt: now + 60_000,
      dailyCount: 1,
      dailyResetAt: now + 86_400_000,
    };
    rateMap.set(ip, entry);
    return { allowed: true };
  }

  // Reset minute window if expired
  if (now > entry.minuteResetAt) {
    entry.minuteCount = 0;
    entry.minuteResetAt = now + 60_000;
  }

  if (entry.dailyCount >= DAILY_LIMIT) {
    const retryAfter = Math.ceil((entry.dailyResetAt - now) / 1000);
    return { allowed: false, retryAfter };
  }

  if (entry.minuteCount >= BURST_LIMIT) {
    const retryAfter = Math.ceil((entry.minuteResetAt - now) / 1000);
    return { allowed: false, retryAfter };
  }

  entry.minuteCount++;
  entry.dailyCount++;
  return { allowed: true };
}

export async function POST(request: Request) {
  // Rate limiting
  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const rateCheck = checkRateLimit(ip);
  if (!rateCheck.allowed) {
    return NextResponse.json(
      { error: "Too many requests. Please wait a moment." },
      {
        status: 429,
        headers: rateCheck.retryAfter
          ? { "Retry-After": String(rateCheck.retryAfter) }
          : undefined,
      }
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
        console.error("[scan/public] Project insert error:", projectError);
        return NextResponse.json(
          { error: "Failed to create project", detail: projectError?.message },
          { status: 500 }
        );
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
      console.error("[scan/public] Scan insert error:", scanError);
      return NextResponse.json(
        { error: "Failed to create scan", detail: scanError?.message },
        { status: 500 }
      );
    }

    return NextResponse.json({ scanId: scan.id, owner, repo, branch });
  } catch (err) {
    console.error("[scan/public] Error:", err);
    const message = err instanceof Error ? err.message : "Failed to access repository";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
