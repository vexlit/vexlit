"use client";

import Link from "next/link";
import { createSupabaseBrowser } from "@/lib/supabase-browser";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { ThemeToggle } from "./theme-toggle";
import { NotificationBell } from "./notification-bell";
import { LanguageSelector } from "./language-selector";

export function Navbar({ email }: { email: string }) {
  const router = useRouter();
  const t = useTranslations("common");

  const handleSignOut = async () => {
    const supabase = createSupabaseBrowser();
    await supabase.auth.signOut();
    router.push("/login");
  };

  return (
    <nav className="border-b border-gray-800 bg-gray-950 sticky top-0 z-50 backdrop-blur-sm bg-gray-950/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-14 items-center">
          <Link href="/" className="text-xl font-bold text-white">
            VEXLIT
          </Link>
          <div className="flex items-center gap-3">
            <NotificationBell />
            <LanguageSelector />
            <ThemeToggle />
            <span className="text-gray-400 text-sm hidden sm:inline">{email}</span>
            <button
              onClick={handleSignOut}
              className="text-gray-400 hover:text-white text-sm transition-colors"
            >
              {t("signOut")}
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}
