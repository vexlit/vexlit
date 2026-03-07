import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { NextResponse } from "next/server";

/** GET /api/policies — list user policies */
export async function GET() {
  const supabase = await createSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const admin = createSupabaseAdmin();
  const { data, error } = await admin
    .from("policies")
    .select("*")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false });

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ policies: data });
}

/** POST /api/policies — create a new policy */
export async function POST(request: Request) {
  const supabase = await createSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  const { name, description, conditions, action, project_id } = body as {
    name: string;
    description?: string;
    conditions: Record<string, unknown>;
    action: string;
    project_id?: string;
  };

  if (!name || !action) {
    return NextResponse.json(
      { error: "name and action are required" },
      { status: 400 }
    );
  }

  if (!["block", "warn", "ignore"].includes(action)) {
    return NextResponse.json(
      { error: "action must be block, warn, or ignore" },
      { status: 400 }
    );
  }

  const admin = createSupabaseAdmin();
  const { data, error } = await admin
    .from("policies")
    .insert({
      user_id: user.id,
      name,
      description: description ?? "",
      conditions: conditions ?? {},
      action,
      project_id: project_id ?? null,
    })
    .select()
    .single();

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ policy: data }, { status: 201 });
}
