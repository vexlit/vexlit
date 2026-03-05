"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export function ScanPolling({ scanId }: { scanId: string }) {
  const router = useRouter();
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setElapsed((prev) => prev + 1);
    }, 1000);

    const poll = setInterval(async () => {
      try {
        const res = await fetch(`/api/scan/${scanId}`);
        if (!res.ok) return;
        const scan = await res.json();
        if (scan.status === "completed" || scan.status === "failed") {
          clearInterval(poll);
          clearInterval(timer);
          router.refresh();
        }
      } catch {
        // ignore network errors, retry on next interval
      }
    }, 2000);

    return () => {
      clearInterval(poll);
      clearInterval(timer);
    };
  }, [scanId, router]);

  return (
    <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-6 text-center">
      <div className="flex items-center justify-center gap-3 mb-2">
        <div className="w-4 h-4 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
        <p className="text-blue-400 font-medium">Scanning in progress...</p>
      </div>
      <p className="text-gray-500 text-sm">
        Elapsed: {elapsed}s — Results will appear automatically.
      </p>
    </div>
  );
}
