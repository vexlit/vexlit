import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { decrypt } from "@/lib/crypto";
import { fetchUserRepos } from "@/lib/github";
import { NextResponse } from "next/server";

export async function GET() {
  const supabase = await createSupabaseServer();
  const {
    data: { session },
  } = await supabase.auth.getSession();

  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Try session provider_token first, fall back to stored token
  let providerToken = session.provider_token;
  if (!providerToken) {
    const admin = createSupabaseAdmin();
    const { data: profile } = await admin
      .from("profiles")
      .select("github_access_token")
      .eq("id", session.user.id)
      .single();
    const encrypted = profile?.github_access_token;
    if (encrypted) {
      try { providerToken = decrypt(encrypted); } catch { providerToken = null; }
    }
  }

  if (!providerToken) {
    return NextResponse.json(
      { error: "GitHub token not available. Please re-login." },
      { status: 401 }
    );
  }

  try {
    const repos = await fetchUserRepos(providerToken);
    return NextResponse.json(
      repos.map((r) => ({
        id: r.id,
        name: r.name,
        full_name: r.full_name,
        private: r.private,
        default_branch: r.default_branch,
        language: r.language,
        updated_at: r.updated_at,
      }))
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
