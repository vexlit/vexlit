"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";

export function ScanPolling({
  scanId,
  createdAt,
}: {
  scanId: string;
  createdAt: string;
}) {
  const router = useRouter();
  const triggered = useRef(false);
  const [elapsed, setElapsed] = useState(() =>
    Math.max(0, Math.floor((Date.now() - new Date(createdAt).getTime()) / 1000))
  );

  useEffect(() => {
    // Timer based on server-side createdAt (survives refresh)
    const timer = setInterval(() => {
      setElapsed(
        Math.max(
          0,
          Math.floor((Date.now() - new Date(createdAt).getTime()) / 1000)
        )
      );
    }, 1000);

    // Trigger scan execution (once)
    if (!triggered.current) {
      triggered.current = true;
      fetch(`/api/scan/${scanId}/execute`, { method: "POST" }).catch(() => {});
    }

    // Poll for completion
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
        // retry on next interval
      }
    }, 2000);

    return () => {
      clearInterval(poll);
      clearInterval(timer);
    };
  }, [scanId, createdAt, router]);

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
