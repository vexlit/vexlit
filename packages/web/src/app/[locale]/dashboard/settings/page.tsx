import { getUser } from "@/lib/auth";
import { createSupabaseAdmin } from "@/lib/supabase-admin";
import { redirect } from "next/navigation";
import { getLocale, getTranslations } from "next-intl/server";
import { SettingsClient } from "@/components/settings-client";
import type { Profile } from "@/lib/types";

export default async function SettingsPage() {
  const locale = await getLocale();
  const user = await getUser();

  if (!user) redirect(`/${locale}/login`);

  const t = await getTranslations("settings");
  const admin = createSupabaseAdmin();
  const { data: profile } = await admin
    .from("profiles")
    .select("*")
    .eq("id", user.id)
    .single();

  return (
    <div className="space-y-8 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">{t("title")}</h1>
        <p className="text-gray-500 text-sm mt-1">{t("subtitle")}</p>
      </div>
      <SettingsClient
        profile={profile as Profile | null}
        email={user.email ?? ""}
      />
    </div>
  );
}
