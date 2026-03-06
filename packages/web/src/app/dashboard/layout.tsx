import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { Navbar } from "@/components/navbar";
import { redirect } from "next/navigation";

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const supabase = await createSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) redirect("/login");

  // Check terms acceptance
  const admin = createSupabaseAdmin();
  const { data: profile } = await admin
    .from("profiles")
    .select("terms_accepted_at")
    .eq("id", user.id)
    .single();

  if (!profile?.terms_accepted_at) {
    redirect("/onboarding/terms");
  }

  return (
    <div className="min-h-screen bg-gray-950">
      <Navbar email={user.email ?? ""} />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>
    </div>
  );
}
