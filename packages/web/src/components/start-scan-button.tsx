"use client";

import { useState } from "react";
import { useRouter } from "@/i18n/navigation";

export function StartScanButton({
  owner,
  repo,
  label,
  small,
}: {
  owner: string;
  repo: string;
  label: string;
  small?: boolean;
}) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);

  const handleClick = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/scan/public", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: `https://github.com/${owner}/${repo}` }),
      });
      const data = await res.json();
      if (data.scanId) {
        router.push(`/scan/${data.scanId}`);
      }
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      onClick={handleClick}
      disabled={loading}
      className={`${
        small ? "px-3 py-1.5 text-xs" : "px-5 py-2.5 text-sm"
      } bg-red-600 rounded-lg font-medium hover:bg-red-700 transition-colors text-white disabled:opacity-50`}
    >
      {loading ? (
        <span className="flex items-center gap-2">
          <span className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
          {label}
        </span>
      ) : (
        label
      )}
    </button>
  );
}
