"use client";

import { Link } from "@/i18n/navigation";
import { useEffect, useState } from "react";
import { createSupabaseBrowser } from "@/lib/supabase-browser";
import { ThemeToggle } from "../theme-toggle";

export function LandingNavActions() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const supabase = createSupabaseBrowser();
    supabase.auth.getSession().then(({ data: { session } }) => {
      setIsLoggedIn(!!session);
      setLoading(false);
    });
  }, []);

  return (
    <div className="flex gap-3 items-center">
      <ThemeToggle />
      {loading ? (
        <div className="w-24" />
      ) : isLoggedIn ? (
        <Link
          href="/dashboard"
          className="px-4 py-2 bg-red-600 rounded-lg text-sm font-medium hover:bg-red-700 transition-colors"
        >
          Dashboard
        </Link>
      ) : (
        <>
          <Link
            href="/login"
            className="text-gray-400 hover:text-white text-sm transition-colors"
          >
            Sign in
          </Link>
          <Link
            href="/login"
            className="px-4 py-2 bg-red-600 rounded-lg text-sm font-medium hover:bg-red-700 transition-colors"
          >
            Get Started
          </Link>
        </>
      )}
    </div>
  );
}
