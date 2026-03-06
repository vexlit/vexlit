import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { encrypt } from "@/lib/crypto";
import { NextResponse } from "next/server";

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get("code");

  if (code) {
    const supabase = await createSupabaseServer();
    const { data: sessionData } = await supabase.auth.exchangeCodeForSession(code);

    // Persist GitHub provider token for later API use
    // (session.provider_token is only available right after OAuth exchange)
    const providerToken = sessionData?.session?.provider_token;

    // Check if user has accepted terms
    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (user) {
      const admin = createSupabaseAdmin();

      // Run token save + terms check in parallel
      const [, { data: profile }] = await Promise.all([
        providerToken
          ? admin
              .from("profiles")
              .update({ github_access_token: encrypt(providerToken) })
              .eq("id", user.id)
          : Promise.resolve(),
        admin
          .from("profiles")
          .select("terms_accepted_at")
          .eq("id", user.id)
          .single(),
      ]);

      if (!profile?.terms_accepted_at) {
        return NextResponse.redirect(`${origin}/onboarding/terms`);
      }
    }
  }

  return NextResponse.redirect(`${origin}/dashboard`);
}
