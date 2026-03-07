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
}

interface NavItem {
  label: string;
  href?: string;
  children?: NavChild[];
}

function useNavItems(): NavItem[] {
  const t = useTranslations("nav");
  return useMemo(() => [
    {
      label: t("product"),
      children: [
        { label: t("liveDemo"), href: "/#scan-input" },
        { label: t("secretDetection"), href: "/#rules" },
        { label: t("aiVerification"), href: "/#how-it-works" },
        { label: t("supportedLanguages"), href: "/#languages" },
      ],
    },
    {
      label: t("resources"),
      children: [
        { label: t("compareTools"), href: "/#comparison" },
        { label: t("securityRules"), href: "/#features" },
      ],
    },
    {
      label: t("cli"),
      children: [
        { label: t("install"), href: "https://www.npmjs.com/package/@vexlit/cli", external: true },
        { label: t("documentation"), href: "/docs" },
        { label: "GitHub", href: "https://github.com/vexlit/vexlit", external: true },
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
                    {child.label}
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
                  {child.label}
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
