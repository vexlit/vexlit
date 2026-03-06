import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { NextResponse } from "next/server";

export async function GET(
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

  const { data: scan } = await supabase
    .from("scans")
    .select("*")
    .eq("id", id)
    .single();

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  return NextResponse.json(scan);
}

export async function DELETE(
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

  // Verify ownership: scan must belong to user's project
  const { data: scan } = await supabase
    .from("scans")
    .select("project_id, projects!inner(user_id)")
    .eq("id", id)
    .single();

  if (!scan) {
    return NextResponse.json({ error: "Not authorized" }, { status: 403 });
  }

  // Use admin client to bypass RLS; ownership already verified above
  const admin = createSupabaseAdmin();
  const { error } = await admin.from("scans").delete().eq("id", id);

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ success: true });
}
