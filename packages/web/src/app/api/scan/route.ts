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

  // Collect file contents
  const fileContents: { path: string; content: string }[] = [];
  for (const file of files) {
    if (file.size > 0) {
      fileContents.push({ path: file.name, content: await file.text() });
    }
  }

  // Create scan record with files stored for worker processing
  const { data: scan, error: scanError } = await admin
    .from("scans")
    .insert({
      project_id: projectId,
      status: "pending",
      file_contents: fileContents,
    })
    .select("id")
    .single();

  if (scanError || !scan) {
    return NextResponse.json(
      { error: "Failed to create scan" },
      { status: 500 }
    );
  }

  // Return immediately — client triggers execution via /api/scan/[id]/execute
  return NextResponse.json({ scanId: scan.id });
}
