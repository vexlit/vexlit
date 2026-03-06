"use client";

import Link from "next/link";
import { useEffect, useState, useRef } from "react";
import { createSupabaseBrowser } from "@/lib/supabase-browser";

// ── Nav menu data ──

interface NavChild {
  label: string;
  description: string;
  href: string;
  icon?: React.ReactNode;
}

interface NavItem {
  label: string;
  href?: string;
  children?: NavChild[];
  badge?: string;
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
  rules: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 010 3.75H5.625a1.875 1.875 0 010-3.75z" />
    </svg>
  ),
  comparison: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
    </svg>
  ),
  changelog: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182M2.985 19.644l3.181-3.183" />
    </svg>
  ),
};

const NAV_ITEMS: NavItem[] = [
  {
    label: "Product",
    children: [
      {
        label: "SAST Scanner",
        description: "See vulnerability detection with before/after examples",
        href: "/#demo",
        icon: DROPDOWN_ICONS.sast,
      },
      {
        label: "Secret Detection",
        description: "200+ detectors for API keys, tokens, and credentials",
        href: "/#rules",
        icon: DROPDOWN_ICONS.secret,
      },
      {
        label: "AI Verification",
        description: "Three-step process from scan to AI-powered fix guidance",
        href: "/#how-it-works",
        icon: DROPDOWN_ICONS.ai,
      },
      {
        label: "Supported Languages",
        description: "JS, TS, Python supported — Go, Java, Rust coming soon",
        href: "/#languages",
        icon: DROPDOWN_ICONS.languages,
      },
    ],
  },
  {
    label: "Docs",
    href: "https://github.com/vexlit/vexlit#readme",
  },
  {
    label: "Resources",
    children: [
      {
        label: "Why VEXLIT",
        description: "Feature comparison with other security tools",
        href: "/#comparison",
        icon: DROPDOWN_ICONS.comparison,
      },
      {
        label: "Security Rules",
        description: "Browse all SAST rules and CWE coverage",
        href: "/#features",
        icon: DROPDOWN_ICONS.rules,
      },
      {
        label: "Changelog",
        description: "Latest updates and new features",
        href: "https://github.com/vexlit/vexlit/releases",
        icon: DROPDOWN_ICONS.changelog,
      },
    ],
  },
  {
    label: "Pricing",
    href: "/#pricing",
  },
];

// ── Dropdown component ──

function NavDropdown({
  item,
  open,
  onToggle,
}: {
  item: NavItem;
  open: boolean;
  onToggle: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        if (open) onToggle();
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [open, onToggle]);

  if (!item.children) {
    const isExternal = item.href?.startsWith("http");
    return (
      <div className="relative flex items-center gap-1">
        {isExternal ? (
          <a
            href={item.href}
            target="_blank"
            rel="noopener noreferrer"
            className="text-gray-300 hover:text-white text-sm font-medium transition-colors px-3 py-2"
          >
            {item.label}
          </a>
        ) : (
          <Link
            href={item.href ?? "/"}
            className="text-gray-300 hover:text-white text-sm font-medium transition-colors px-3 py-2"
          >
            {item.label}
          </Link>
        )}
        {item.badge && (
          <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-400 font-medium leading-none">
            {item.badge}
          </span>
        )}
      </div>
    );
  }

  return (
    <div ref={ref} className="relative">
      <button
        onClick={onToggle}
        className="flex items-center gap-1 text-gray-300 hover:text-white text-sm font-medium transition-colors px-3 py-2"
      >
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
        <div className="absolute top-full left-0 mt-2 w-72 bg-gray-900 border border-gray-800 rounded-xl shadow-2xl shadow-black/40 py-2 z-50">
          {item.children.map((child) => {
            const isExternal = child.href.startsWith("http");
            const Comp = isExternal ? "a" : Link;
            const extraProps = isExternal
              ? { target: "_blank", rel: "noopener noreferrer" }
              : {};
            return (
              <Comp
                key={child.label}
                href={child.href}
                {...(extraProps as Record<string, string>)}
                className="flex items-start gap-3 px-4 py-3 hover:bg-gray-800/60 transition-colors"
                onClick={() => onToggle()}
              >
                {child.icon && (
                  <span className="text-gray-400 mt-0.5 flex-shrink-0">{child.icon}</span>
                )}
                <div>
                  <p className="text-white text-sm font-medium">{child.label}</p>
                  <p className="text-gray-500 text-xs mt-0.5">{child.description}</p>
                </div>
              </Comp>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Mobile menu ──

function MobileMenu({
  open,
  onClose,
  isLoggedIn,
  loading,
}: {
  open: boolean;
  onClose: () => void;
  isLoggedIn: boolean;
  loading: boolean;
}) {
  useEffect(() => {
    if (open) {
      document.body.style.overflow = "hidden";
      return () => { document.body.style.overflow = ""; };
    }
  }, [open]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 lg:hidden">
      <div className="fixed inset-0 bg-black/60" onClick={onClose} />
      <div className="fixed top-0 right-0 w-80 max-w-[85vw] h-full bg-gray-950 border-l border-gray-800 overflow-y-auto">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <span className="text-white font-bold text-lg">VEXLIT</span>
          <button onClick={onClose} className="text-gray-400 hover:text-white p-1">
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="px-6 py-4 space-y-1">
          {NAV_ITEMS.map((item) => (
            <div key={item.label}>
              {item.children ? (
                <div className="py-2">
                  <p className="text-gray-500 text-xs font-semibold uppercase tracking-wider mb-2">
                    {item.label}
                  </p>
                  {item.children.map((child) => {
                    const isExternal = child.href.startsWith("http");
                    const Comp = isExternal ? "a" : Link;
                    const extraProps = isExternal
                      ? { target: "_blank", rel: "noopener noreferrer" }
                      : {};
                    return (
                      <Comp
                        key={child.label}
                        href={child.href}
                        {...(extraProps as Record<string, string>)}
                        className="block py-2 text-gray-300 hover:text-white text-sm transition-colors"
                        onClick={onClose}
                      >
                        {child.label}
                      </Comp>
                    );
                  })}
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  {item.href?.startsWith("http") ? (
                    <a
                      href={item.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block py-2 text-gray-300 hover:text-white text-sm font-medium transition-colors"
                      onClick={onClose}
                    >
                      {item.label}
                    </a>
                  ) : (
                    <Link
                      href={item.href ?? "/"}
                      className="block py-2 text-gray-300 hover:text-white text-sm font-medium transition-colors"
                      onClick={onClose}
                    >
                      {item.label}
                    </Link>
                  )}
                  {item.badge && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-400 font-medium">
                      {item.badge}
                    </span>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>

        <div className={`px-6 py-4 border-t border-gray-800 space-y-3 transition-opacity ${loading ? "opacity-0 pointer-events-none" : "opacity-100"}`}>
          {isLoggedIn ? (
            <Link
              href="/dashboard"
              className="block w-full text-center px-4 py-2.5 bg-red-600 rounded-lg text-sm font-medium hover:bg-red-700 transition-colors text-white"
              onClick={onClose}
            >
              Dashboard
            </Link>
          ) : (
            <>
              <Link
                href="/login"
                className="block w-full text-center px-4 py-2.5 border border-gray-700 rounded-lg text-sm font-medium text-gray-300 hover:border-gray-500 hover:text-white transition-colors"
                onClick={onClose}
              >
                Sign in
              </Link>
              <button
                onClick={() => {
                  onClose();
                  setTimeout(() => {
                    const el = document.getElementById("scan-input");
                    if (el) {
                      el.scrollIntoView({ behavior: "smooth" });
                      setTimeout(() => {
                        el.querySelector<HTMLInputElement>("input")?.focus();
                      }, 500);
                    }
                  }, 300);
                }}
                className="block w-full text-center px-4 py-2.5 bg-red-600 rounded-lg text-sm font-medium hover:bg-red-700 transition-colors text-white"
              >
                Scan Repo
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Main nav ──

export function LandingNav() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [loading, setLoading] = useState(true);
  const [openDropdown, setOpenDropdown] = useState<string | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const supabase = createSupabaseBrowser();
    supabase.auth.getSession().then(({ data: { session } }) => {
      setIsLoggedIn(!!session);
      setLoading(false);
    });
  }, []);

  return (
    <nav className="fixed top-0 w-full z-50 border-b border-gray-800 bg-gray-950/80 backdrop-blur-sm">
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        {/* Left: Logo + Nav links */}
        <div className="flex items-center gap-1">
          <Link href="/" className="text-xl font-bold text-white mr-6">
            VEXLIT
          </Link>

          {/* Desktop nav items */}
          <div className="hidden lg:flex items-center">
            {NAV_ITEMS.map((item) => (
              <NavDropdown
                key={item.label}
                item={item}
                open={openDropdown === item.label}
                onToggle={() =>
                  setOpenDropdown((prev) => (prev === item.label ? null : item.label))
                }
              />
            ))}
          </div>
        </div>

        {/* Right: Auth actions */}
        <div className="flex items-center gap-3">
          {/* GitHub star link */}
          <a
            href="https://github.com/vexlit/vexlit"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden sm:flex items-center gap-1.5 text-gray-400 hover:text-white text-sm transition-colors"
          >
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
              <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
            </svg>
          </a>

          {/* Desktop auth buttons */}
          <div className="hidden lg:flex items-center gap-3">
            <div className={`flex items-center gap-3 transition-opacity ${loading ? "opacity-0 pointer-events-none" : "opacity-100"}`}>
              {isLoggedIn ? (
                <Link
                  href="/dashboard"
                  className="px-4 py-2 bg-red-600 rounded-lg text-sm font-medium hover:bg-red-700 transition-colors text-white"
                >
                  Dashboard
                </Link>
              ) : (
                <>
                  <Link
                    href="/login"
                    className="text-gray-400 hover:text-white text-sm font-medium transition-colors px-3 py-2"
                  >
                    Sign in
                  </Link>
                  <button
                    onClick={() => {
                      const el = document.getElementById("scan-input");
                      if (el) {
                        el.scrollIntoView({ behavior: "smooth" });
                        setTimeout(() => {
                          el.querySelector<HTMLInputElement>("input")?.focus();
                        }, 500);
                      }
                    }}
                    className="px-4 py-2 bg-red-600 rounded-lg text-sm font-medium hover:bg-red-700 transition-colors text-white"
                  >
                    Scan Repo
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Mobile hamburger */}
          <button
            onClick={() => setMobileOpen(true)}
            className="lg:hidden text-gray-400 hover:text-white p-1.5"
          >
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
            </svg>
          </button>
        </div>
      </div>

      <MobileMenu
        open={mobileOpen}
        onClose={() => setMobileOpen(false)}
        isLoggedIn={isLoggedIn}
        loading={loading}
      />
    </nav>
  );
}
