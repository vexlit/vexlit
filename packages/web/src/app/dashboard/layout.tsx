import { createSupabaseServer } from "@/lib/supabase-server";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { Navbar } from "@/components/navbar";
import { Sidebar } from "@/components/sidebar";
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
      <div className="flex">
        <Sidebar />
        <main className="flex-1 min-w-0 px-4 sm:px-6 lg:px-8 py-8 pb-20 lg:pb-8">
          {children}
        </main>
      </div>
    </div>
  );
}
