import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { NextResponse } from "next/server";

export async function GET() {
  const supabase = await createSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const admin = createSupabaseAdmin();
  const { data: profile } = await admin
    .from("profiles")
    .select("*")
    .eq("id", user.id)
    .single();

  return NextResponse.json({ profile });
}

export async function POST(request: Request) {
  const supabase = await createSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();

  // Server-side webhook URL validation (SSRF prevention)
  if (body.slack_webhook_url && !isValidWebhookUrl(body.slack_webhook_url, "slack")) {
    return NextResponse.json({ error: "Invalid Slack webhook URL" }, { status: 400 });
  }
  if (body.discord_webhook_url && !isValidWebhookUrl(body.discord_webhook_url, "discord")) {
    return NextResponse.json({ error: "Invalid Discord webhook URL" }, { status: 400 });
  }

  const admin = createSupabaseAdmin();

  // Check if profile exists
  const { data: existing } = await admin
    .from("profiles")
    .select("id")
    .eq("id", user.id)
    .single();

  if (existing) {
    const { error } = await admin
      .from("profiles")
      .update({ ...body, updated_at: new Date().toISOString() })
      .eq("id", user.id);

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 });
    }
  } else {
    const { error } = await admin
      .from("profiles")
      .insert({ id: user.id, ...body });

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 });
    }
  }

  return NextResponse.json({ success: true });
}

function isValidWebhookUrl(url: string, type: "slack" | "discord"): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return false;
    if (type === "slack") {
      return parsed.hostname === "hooks.slack.com" || parsed.hostname === "hooks.slack-gov.com";
    }
    return (
      (parsed.hostname === "discord.com" || parsed.hostname === "discordapp.com") &&
      parsed.pathname.startsWith("/api/webhooks/")
    );
  } catch {
    return false;
  }
}
