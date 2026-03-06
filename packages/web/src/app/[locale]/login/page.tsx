import { createSupabaseServer } from "@/lib/supabase-server";
import { redirect } from "next/navigation";
import { getLocale, getTranslations } from "next-intl/server";
import { LoginButton } from "./login-button";

export default async function LoginPage() {
  const locale = await getLocale();
  const supabase = await createSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (user) redirect(`/${locale}/dashboard`);

  const t = await getTranslations("login");

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950">
      <div className="max-w-md w-full space-y-8 p-8">
        <div className="text-center">
          <h1 className="text-4xl font-bold text-white">{t("title")}</h1>
          <p className="mt-2 text-gray-400">{t("subtitle")}</p>
        </div>

        <LoginButton />
      </div>
    </div>
  );
}
