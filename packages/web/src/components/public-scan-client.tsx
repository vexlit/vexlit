"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "@/i18n/navigation";
import { useTranslations } from "next-intl";

export function PublicScanClient({
  scanId,
  createdAt,
}: {
  scanId: string;
  createdAt: string;
}) {
  const t = useTranslations("publicScan");
  const router = useRouter();
  const executing = useRef(false);
  const [elapsed, setElapsed] = useState(() =>
    Math.max(0, Math.floor((Date.now() - new Date(createdAt).getTime()) / 1000))
  );
  const [phase, setPhase] = useState<string>("starting");
  const [progress, setProgress] = useState<string>("");

  useEffect(() => {
    let stopped = false;

    const timer = setInterval(() => {
      setElapsed(
        Math.max(0, Math.floor((Date.now() - new Date(createdAt).getTime()) / 1000))
      );
    }, 1000);

    async function runExecute() {
      if (executing.current || stopped) return;
      executing.current = true;

      try {
        const res = await fetch(`/api/scan/public/${scanId}/execute`, {
          method: "POST",
        });
        if (!res.ok) {
          executing.current = false;
          return;
        }
        const data = await res.json();

        if (data.phase === "fetching") {
          setPhase("fetching");
          if (data.total) {
            const fetched = data.total - data.remaining;
            setProgress(t("progressFetching", { fetched, total: data.total }));
          }
        } else if (data.phase === "scanning") {
          setPhase("scanning");
          if (data.remaining) {
            setProgress(t("progressScanning", { remaining: data.remaining }));
          }
        }

        if (data.status === "completed" || data.status === "failed") {
          clearInterval(timer);
          if (!stopped) router.refresh();
          return;
        }

        if (data.status === "running") {
          executing.current = false;
          if (!stopped) setTimeout(runExecute, 500);
          return;
        }
      } catch {
        // retry
      }
      executing.current = false;
    }

    runExecute();

    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [scanId, createdAt, router]);

  const phaseText: Record<string, string> = {
    starting: t("phaseStarting"),
    fetching: t("phaseFetching"),
    scanning: t("phaseScanning"),
  };

  return (
    <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-8 text-center">
      <div className="flex items-center justify-center gap-3 mb-3">
        <div className="w-5 h-5 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
        <p className="text-blue-400 font-medium text-lg">{t("scanningInProgress")}</p>
      </div>
      <p className="text-gray-400 text-sm">{phaseText[phase] ?? phaseText.starting}</p>
      {progress && (
        <p className="text-gray-500 text-xs mt-1">{progress}</p>
      )}
      <p className="text-gray-600 text-xs mt-3">
        {t("elapsed", { time: elapsed })}
      </p>
    </div>
  );
}
