"use client";

import { useState } from "react";
import { useRouter } from "@/i18n/navigation";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

export function QuickRescan({ projectId }: { projectId: string }) {
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const t = useTranslations("quickRescan");

  const handleRescan = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ projectId }),
      });
      const data = await res.json();
      if (!res.ok) {
        const code = data.errorCode;
        toast.error(code ? t(code) : (data.error ?? t("failed")));
        return;
      }
      toast.success(t("started"));
      router.push(`/dashboard/scans/${data.scanId}`);
    } catch {
      toast.error(t("networkError"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      onClick={handleRescan}
      disabled={loading}
      className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-colors disabled:opacity-50"
      title={t("title")}
    >
      {loading ? (
        <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      ) : (
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182" />
        </svg>
      )}
    </button>
  );
}
