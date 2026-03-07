"use client";

import { useState, useRef, useEffect } from "react";
import { createSupabaseBrowser } from "@/lib/supabase-browser";
import { Link, useRouter } from "@/i18n/navigation";
import { useTranslations } from "next-intl";
import { ThemeToggle } from "./theme-toggle";
import { NotificationBell } from "./notification-bell";
import { LanguageSelector } from "./language-selector";
import { VexlitLogo } from "./vexlit-logo";

export function Navbar({ email }: { email: string }) {
  const router = useRouter();
  const t = useTranslations("common");
  const [profileOpen, setProfileOpen] = useState(false);
  const profileRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (profileRef.current && !profileRef.current.contains(e.target as Node)) {
        setProfileOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleSignOut = async () => {
    const supabase = createSupabaseBrowser();
    await supabase.auth.signOut();
    router.push("/login");
  };

  const initial = email.charAt(0).toUpperCase();

  return (
    <nav className="border-b border-gray-800 bg-gray-950 sticky top-0 z-50 backdrop-blur-sm bg-gray-950/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-14 items-center">
          <div className="flex items-center gap-6">
            <Link href="/" className="flex items-center gap-2 text-xl font-bold text-white">
              <VexlitLogo size={28} />
              VEXLIT
            </Link>
            <div className="hidden lg:flex items-center gap-1">
              <Link href="/" className="text-gray-400 hover:text-white text-sm font-medium transition-colors px-2.5 py-1.5 rounded-lg hover:bg-gray-800/50">
                {t("home")}
              </Link>
              <Link href="/docs" className="text-gray-400 hover:text-white text-sm font-medium transition-colors px-2.5 py-1.5 rounded-lg hover:bg-gray-800/50">
                Docs
              </Link>
              <Link href="/pricing" className="text-gray-400 hover:text-white text-sm font-medium transition-colors px-2.5 py-1.5 rounded-lg hover:bg-gray-800/50">
                Pricing
              </Link>
              <a href="https://github.com/vexlit/vexlit" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white text-sm font-medium transition-colors px-2.5 py-1.5 rounded-lg hover:bg-gray-800/50">
                {t("github")}
              </a>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <NotificationBell />
            <LanguageSelector />
            <ThemeToggle />
            <div className="relative" ref={profileRef}>
              <button
                onClick={() => setProfileOpen(!profileOpen)}
                className="w-8 h-8 rounded-full bg-purple-600 text-white text-sm font-medium flex items-center justify-center hover:bg-purple-500 transition-colors"
              >
                {initial}
              </button>
              {profileOpen && (
                <div className="absolute right-0 mt-2 w-64 bg-gray-900 border border-gray-800 rounded-xl shadow-lg py-2 z-50">
                  <div className="px-4 py-2 border-b border-gray-800">
                    <p className="text-sm text-gray-300 truncate">{email}</p>
                  </div>
                  <Link
                    href="/dashboard/settings"
                    onClick={() => setProfileOpen(false)}
                    className="block px-4 py-2 text-sm text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
                  >
                    {t("settings")}
                  </Link>
                  <button
                    onClick={handleSignOut}
                    className="w-full text-left px-4 py-2 text-sm text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
                  >
                    {t("signOut")}
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}
