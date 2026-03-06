import { getUser } from "@/lib/auth";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { redirect } from "next/navigation";
import { SettingsClient } from "@/components/settings-client";
import type { Profile } from "@/lib/types";

export default async function SettingsPage() {
  const user = await getUser();

  if (!user) redirect("/login");

  const admin = createSupabaseAdmin();
  const { data: profile } = await admin
    .from("profiles")
    .select("*")
    .eq("id", user.id)
    .single();

  return (
    <div className="space-y-8 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-gray-500 text-sm mt-1">
          Manage your account and preferences
        </p>
      </div>
      <SettingsClient
        profile={profile as Profile | null}
        email={user.email ?? ""}
      />
    </div>
  );
}
