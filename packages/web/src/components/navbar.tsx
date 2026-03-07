"use client";

import { useState, useRef, useEffect, useMemo } from "react";
import { createSupabaseBrowser } from "@/lib/supabase-browser";
import { Link, useRouter } from "@/i18n/navigation";
import { useTranslations } from "next-intl";
import { ThemeToggle } from "./theme-toggle";
import { NotificationBell } from "./notification-bell";
import { LanguageSelector } from "./language-selector";
import { VexlitLogo } from "./vexlit-logo";

/* ── Nav dropdown items (same structure as landing nav) ── */

interface NavChild {
  label: string;
  href: string;
  external?: boolean;
  icon?: React.ReactNode;
}

interface NavItem {
  label: string;
  href?: string;
  children?: NavChild[];
}

const DROPDOWN_ICONS = {
  sast: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
  ),
  secret: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
    </svg>
  ),
  ai: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456z" />
    </svg>
  ),
  languages: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
    </svg>
  ),
  comparison: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
    </svg>
  ),
  rules: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 010 3.75H5.625a1.875 1.875 0 010-3.75z" />
    </svg>
  ),
  install: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 8.25H7.5a2.25 2.25 0 00-2.25 2.25v9a2.25 2.25 0 002.25 2.25h9a2.25 2.25 0 002.25-2.25v-9a2.25 2.25 0 00-2.25-2.25H15M9 12l3 3m0 0l3-3m-3 3V2.25" />
    </svg>
  ),
  docs: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25" />
    </svg>
  ),
  github: (
    <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
      <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
    </svg>
  ),
  vscode: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3M4.5 19.5h15a2.25 2.25 0 002.25-2.25V6.75A2.25 2.25 0 0019.5 4.5h-15A2.25 2.25 0 002.25 6.75v10.5A2.25 2.25 0 004.5 19.5z" />
    </svg>
  ),
};

function useNavItems(): NavItem[] {
  const t = useTranslations("nav");
  return useMemo(() => [
    {
      label: t("product"),
      children: [
        { label: t("liveDemo"), href: "/#scan-input", icon: DROPDOWN_ICONS.sast },
        { label: t("secretDetection"), href: "/#rules", icon: DROPDOWN_ICONS.secret },
        { label: t("aiVerification"), href: "/#how-it-works", icon: DROPDOWN_ICONS.ai },
        { label: t("supportedLanguages"), href: "/#languages", icon: DROPDOWN_ICONS.languages },
        { label: t("vscodeExtension"), href: "/vscode", icon: DROPDOWN_ICONS.vscode },
      ],
    },
    {
      label: t("resources"),
      children: [
        { label: t("compareTools"), href: "/#comparison", icon: DROPDOWN_ICONS.comparison },
        { label: t("securityRules"), href: "/#features", icon: DROPDOWN_ICONS.rules },
      ],
    },
    {
      label: t("cli"),
      children: [
        { label: t("install"), href: "https://www.npmjs.com/package/@vexlit/cli", external: true, icon: DROPDOWN_ICONS.install },
        { label: t("documentation"), href: "/docs", icon: DROPDOWN_ICONS.docs },
        { label: "GitHub", href: "https://github.com/vexlit/vexlit", external: true, icon: DROPDOWN_ICONS.github },
      ],
    },
    { label: t("pricing"), href: "/pricing" },
  ], [t]);
}

/* ── Dropdown component ── */

function NavDropdown({
  item,
  open,
  onOpen,
  onClose,
}: {
  item: NavItem;
  open: boolean;
  onOpen: () => void;
  onClose: () => void;
}) {
  const closeTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  const handleMouseEnter = () => {
    clearTimeout(closeTimer.current);
    onOpen();
  };

  const handleMouseLeave = () => {
    closeTimer.current = setTimeout(onClose, 150);
  };

  useEffect(() => () => clearTimeout(closeTimer.current), []);

  if (!item.children) {
    return (
      <Link
        href={item.href ?? "/"}
        className="text-gray-400 hover:text-white text-sm font-medium transition-colors px-2.5 py-1.5 rounded-lg hover:bg-gray-800/50"
      >
        {item.label}
      </Link>
    );
  }

  return (
    <div
      className="relative"
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      <button className="flex items-center gap-1 text-gray-400 hover:text-white text-sm font-medium transition-colors px-2.5 py-1.5 rounded-lg hover:bg-gray-800/50">
        {item.label}
        <svg
          className={`w-3.5 h-3.5 transition-transform ${open ? "rotate-180" : ""}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
        </svg>
      </button>

      {open && (
        <div className="absolute top-full left-0 pt-2 z-50">
          <div className="w-56 bg-gray-900 border border-gray-800 rounded-xl shadow-2xl shadow-black/40 py-2">
            {item.children.map((child) => {
              const content = (
                <span className="flex items-center gap-3">
                  {child.icon && <span className="text-gray-500 flex-shrink-0">{child.icon}</span>}
                  {child.label}
                </span>
              );
              if (child.external) {
                return (
                  <a
                    key={child.label}
                    href={child.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block px-4 py-2.5 text-sm text-gray-300 hover:text-white hover:bg-gray-800/60 transition-colors"
                    onClick={onClose}
                  >
                    {content}
                  </a>
                );
              }
              return (
                <Link
                  key={child.label}
                  href={child.href}
                  className="block px-4 py-2.5 text-sm text-gray-300 hover:text-white hover:bg-gray-800/60 transition-colors"
                  onClick={onClose}
                >
                  {content}
                </Link>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Main Navbar ── */

export function Navbar({ email }: { email: string }) {
  const router = useRouter();
  const t = useTranslations("common");
  const [profileOpen, setProfileOpen] = useState(false);
  const [openDropdown, setOpenDropdown] = useState<string | null>(null);
  const profileRef = useRef<HTMLDivElement>(null);
  const navItems = useNavItems();

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
              {navItems.map((item) => (
                <NavDropdown
                  key={item.label}
                  item={item}
                  open={openDropdown === item.label}
                  onOpen={() => setOpenDropdown(item.label)}
                  onClose={() => setOpenDropdown(null)}
                />
              ))}
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
