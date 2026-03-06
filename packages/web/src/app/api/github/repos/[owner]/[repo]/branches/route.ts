import { createSupabaseServer } from "@/lib/supabase-server";
import { fetchBranches } from "@/lib/github";
import { NextResponse } from "next/server";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ owner: string; repo: string }> }
) {
  const { owner, repo } = await params;
  const supabase = await createSupabaseServer();
  const {
    data: { session },
  } = await supabase.auth.getSession();

  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const providerToken = session.provider_token;
  if (!providerToken) {
    return NextResponse.json(
      { error: "GitHub token not available. Please re-login." },
      { status: 401 }
    );
  }

  try {
    const branches = await fetchBranches(owner, repo, providerToken);
    return NextResponse.json(
      branches.map((b) => ({
        name: b.name,
        sha: b.commit.sha,
      }))
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
