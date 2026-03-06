import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { NextResponse } from "next/server";

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get("code");

  if (code) {
    const supabase = await createSupabaseServer();
    await supabase.auth.exchangeCodeForSession(code);

    // Check if user has accepted terms
    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (user) {
      const admin = createSupabaseAdmin();
      const { data: profile } = await admin
        .from("profiles")
        .select("terms_accepted_at")
        .eq("id", user.id)
        .single();

      if (!profile?.terms_accepted_at) {
        return NextResponse.redirect(`${origin}/onboarding/terms`);
      }
    }
  }

  return NextResponse.redirect(`${origin}/dashboard`);
}
