import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { fetchDefaultBranch } from "@/lib/github";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const supabase = await createSupabaseServer();
  const {
    data: { session },
  } = await supabase.auth.getSession();

  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const user = session.user;
  const contentType = request.headers.get("content-type") ?? "";
  const isJson = contentType.includes("application/json");

  let projectName: string;
  let githubUrl: string | null = null;
  let fileContents: { path: string; content: string }[] | null = null;
  let commitSha: string | null = null;
  let branch: string | null = null;
  let githubMeta: { owner: string; repo: string; branch: string } | null =
    null;

  if (isJson) {
    // GitHub repo scan — store metadata only, defer file fetching to execute
    const body = await request.json();
    const { owner, repo, branch: selectedBranch } = body as {
      owner: string;
      repo: string;
      branch?: string;
    };

    if (!owner || !repo) {
      return NextResponse.json(
        { error: "owner and repo are required" },
        { status: 400 }
      );
    }

    const providerToken = session.provider_token;
    if (!providerToken) {
      return NextResponse.json(
        { error: "GitHub token not available. Please re-login." },
        { status: 401 }
      );
    }

    projectName = `${owner}/${repo}`;
    githubUrl = `https://github.com/${owner}/${repo}`;

    // Determine branch (lightweight — 1-2 API calls only)
    const branchInfo = selectedBranch
      ? { branch: selectedBranch, sha: "" }
      : await fetchDefaultBranch(owner, repo, providerToken);
    branch = branchInfo.branch;
    commitSha = branchInfo.sha || null;

    // Store GitHub params for deferred fetch in execute route
    githubMeta = { owner, repo, branch };
  } else {
    // File upload scan (existing flow)
    const formData = await request.formData();
    projectName = formData.get("projectName") as string;
    githubUrl = (formData.get("githubUrl") as string) || null;
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

    projectName = projectName.trim();

    fileContents = [];
    for (const file of files) {
      if (file.size > 0) {
        fileContents.push({ path: file.name, content: await file.text() });
      }
    }
  }

  const admin = createSupabaseAdmin();

  // Create or find project
  let projectId: string;
  const { data: existingProject } = await admin
    .from("projects")
    .select("id")
    .eq("user_id", user.id)
    .eq("name", projectName)
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
        name: projectName,
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

  // Create scan record
  const { data: scan, error: scanError } = await admin
    .from("scans")
    .insert({
      project_id: projectId,
      status: "pending",
      file_contents: fileContents,
      github_meta: githubMeta,
      commit_sha: commitSha,
      branch,
    })
    .select("id, github_meta")
    .single();

  if (scanError || !scan) {
    return NextResponse.json(
      { error: scanError?.message ?? "Failed to create scan" },
      { status: 500 }
    );
  }

  // Verify github_meta was actually stored (column may not exist yet)
  if (githubMeta && !scan.github_meta) {
    await admin.from("scans").delete().eq("id", scan.id);
    return NextResponse.json(
      {
        error:
          "Database schema outdated. Run migration: ALTER TABLE scans ADD COLUMN IF NOT EXISTS github_meta jsonb;",
      },
      { status: 500 }
    );
  }

  return NextResponse.json({ scanId: scan.id });
}
