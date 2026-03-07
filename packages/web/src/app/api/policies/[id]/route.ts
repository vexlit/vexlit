import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { NextResponse } from "next/server";

/** PUT /api/policies/[id] — update a policy */
export async function PUT(
  request: Request,
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

  // Verify ownership
  const { data: existing } = await admin
    .from("policies")
    .select("user_id")
    .eq("id", id)
    .single();

  if (!existing || existing.user_id !== user.id) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const body = await request.json();
  const { name, description, conditions, action, enabled, project_id } =
    body as {
      name?: string;
      description?: string;
      conditions?: Record<string, unknown>;
      action?: string;
      enabled?: boolean;
      project_id?: string | null;
    };

  if (action && !["block", "warn", "ignore"].includes(action)) {
    return NextResponse.json(
      { error: "action must be block, warn, or ignore" },
      { status: 400 }
    );
  }

  const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
  if (name !== undefined) updates.name = name;
  if (description !== undefined) updates.description = description;
  if (conditions !== undefined) updates.conditions = conditions;
  if (action !== undefined) updates.action = action;
  if (enabled !== undefined) updates.enabled = enabled;
  if (project_id !== undefined) updates.project_id = project_id;

  const { data, error } = await admin
    .from("policies")
    .update(updates)
    .eq("id", id)
    .select()
    .single();

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ policy: data });
}

/** DELETE /api/policies/[id] — delete a policy */
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

  const admin = createSupabaseAdmin();

  // Verify ownership
  const { data: existing } = await admin
    .from("policies")
    .select("user_id")
    .eq("id", id)
    .single();

  if (!existing || existing.user_id !== user.id) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  await admin.from("policies").delete().eq("id", id);
  return NextResponse.json({ ok: true });
}
