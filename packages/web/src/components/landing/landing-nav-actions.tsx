"use client";

import Link from "next/link";
import { ThemeToggle } from "../theme-toggle";

export function LandingNavActions() {
  return (
    <div className="flex gap-3 items-center">
      <ThemeToggle />
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
    </div>
  );
}
