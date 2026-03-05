"use client";

import Link from "next/link";
import { createSupabaseBrowser } from "@/lib/supabase-browser";
import { useRouter } from "next/navigation";

export function Navbar({ email }: { email: string }) {
  const router = useRouter();

  const handleSignOut = async () => {
    const supabase = createSupabaseBrowser();
    await supabase.auth.signOut();
    router.push("/login");
  };

  return (
    <nav className="border-b border-gray-800 bg-gray-950">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-14 items-center">
          <div className="flex items-center gap-8">
            <Link href="/dashboard" className="text-xl font-bold text-white">
              VEXLIT
            </Link>
            <div className="flex gap-4">
              <Link
                href="/dashboard"
                className="text-gray-400 hover:text-white text-sm"
              >
                Dashboard
              </Link>
              <Link
                href="/dashboard/new"
                className="text-gray-400 hover:text-white text-sm"
              >
                New Scan
              </Link>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-gray-400 text-sm">{email}</span>
            <button
              onClick={handleSignOut}
              className="text-gray-400 hover:text-white text-sm"
            >
              Sign out
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}
