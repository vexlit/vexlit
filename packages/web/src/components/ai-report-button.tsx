"use client";

import { useState } from "react";
import { useTranslations, useLocale } from "next-intl";
import { getAiCache, setAiCache } from "@/lib/ai-cache";

export function AiReportButton({ scanId }: { scanId: string }) {
  const t = useTranslations("aiReport");
  const locale = useLocale();
  const cacheKey = `vexlit-ai-${scanId}-report-${locale}`;
  const [report, setReport] = useState<string | null>(() =>
    getAiCache(cacheKey)
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [open, setOpen] = useState(false);

  const handleReport = async () => {
    if (report) {
      setOpen(!open);
      return;
    }

    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/ai/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanId, locale }),
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.error ?? "Failed to generate report");
        return;
      }

      setReport(data.report);
      setAiCache(cacheKey, data.report);
      setOpen(true);
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = () => {
    if (!report) return;
    const blob = new Blob([report], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security-report-${scanId.slice(0, 8)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <button
        onClick={handleReport}
        disabled={loading}
        className="px-4 py-2 rounded-lg border border-purple-500/30 text-purple-400 hover:bg-purple-500/10 transition-colors disabled:opacity-50 text-sm font-medium"
      >
        {loading ? (
          <span className="flex items-center gap-2">
            <span className="w-4 h-4 border-2 border-purple-400 border-t-transparent rounded-full animate-spin" />
            {t("generatingReport")}
          </span>
        ) : open ? (
          t("hideReport")
        ) : (
          t("generateReport")
        )}
      </button>

      {error && <p className="text-red-400 text-sm mt-2">{error}</p>}

      {open && report && (
        <div className="mt-4 bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
            <span className="text-sm font-medium text-white">
              {t("reportTitle")}
            </span>
            <button
              onClick={handleDownload}
              className="text-xs px-3 py-1 rounded bg-gray-800 text-gray-300 hover:text-white hover:bg-gray-700 transition-colors"
            >
              {t("download")}
            </button>
          </div>
          <div className="p-4 prose prose-invert prose-sm max-w-none text-gray-300">
            <ReportRenderer content={report} />
          </div>
        </div>
      )}
    </div>
  );
}

function ReportRenderer({ content }: { content: string }) {
  const lines = content.split("\n");
  const elements: React.ReactNode[] = [];
  let inCodeBlock = false;
  let codeLines: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.startsWith("```")) {
      if (inCodeBlock) {
        elements.push(
          <pre
            key={`code-${i}`}
            className="bg-gray-950 rounded p-3 text-xs font-mono overflow-x-auto my-2"
          >
            {codeLines.join("\n")}
          </pre>
        );
        codeLines = [];
        inCodeBlock = false;
      } else {
        inCodeBlock = true;
      }
      continue;
    }

    if (inCodeBlock) {
      codeLines.push(line);
      continue;
    }

    if (line.startsWith("#### ")) {
      elements.push(
        <h4 key={i} className="font-semibold text-white mt-3 mb-1 text-sm">
          {line.slice(5)}
        </h4>
      );
    } else if (line.startsWith("### ")) {
      elements.push(
        <h3 key={i} className="font-semibold text-white mt-4 mb-1">
          {line.slice(4)}
        </h3>
      );
    } else if (line.startsWith("## ")) {
      elements.push(
        <h2
          key={i}
          className="font-bold text-white mt-6 mb-2 text-lg border-b border-gray-800 pb-2"
        >
          {line.slice(3)}
        </h2>
      );
    } else if (line.startsWith("# ")) {
      elements.push(
        <h1 key={i} className="font-bold text-white mt-4 mb-3 text-xl">
          {line.slice(2)}
        </h1>
      );
    } else if (line.startsWith("- ") || line.startsWith("* ")) {
      elements.push(
        <li key={i} className="ml-4 list-disc text-sm">
          <InlineText text={line.slice(2)} />
        </li>
      );
    } else if (/^\d+\.\s/.test(line)) {
      const text = line.replace(/^\d+\.\s/, "");
      elements.push(
        <li key={i} className="ml-4 list-decimal text-sm">
          <InlineText text={text} />
        </li>
      );
    } else if (line.trim() === "") {
      elements.push(<br key={i} />);
    } else {
      elements.push(
        <p key={i} className="my-1 text-sm">
          <InlineText text={line} />
        </p>
      );
    }
  }

  return <>{elements}</>;
}

function InlineText({ text }: { text: string }) {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return (
    <>
      {parts.map((part, i) => {
        if (part.startsWith("**") && part.endsWith("**")) {
          return (
            <strong key={i} className="text-white">
              {part.slice(2, -2)}
            </strong>
          );
        }
        if (part.startsWith("`") && part.endsWith("`")) {
          return (
            <code
              key={i}
              className="bg-gray-800 px-1 rounded text-xs font-mono"
            >
              {part.slice(1, -1)}
            </code>
          );
        }
        return <span key={i}>{part}</span>;
      })}
    </>
  );
}
