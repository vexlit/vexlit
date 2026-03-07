"use client";

import { useState } from "react";
import { useTranslations, useLocale } from "next-intl";
import { getAiCache, setAiCache } from "@/lib/ai-cache";

interface Props {
  scanId: string;
  vulnId: string;
  ruleName: string;
  severity: string;
  message: string;
  filePath: string;
  line: number;
  snippet: string | null;
  cwe: string | null;
  owasp: string | null;
}

export function AiExplainButton({ scanId, vulnId, ...props }: Props) {
  const t = useTranslations("aiExplain");
  const locale = useLocale();
  const cacheKey = `vexlit-ai-${scanId}-${vulnId}-explain-${locale}`;
  const [explanation, setExplanation] = useState<string | null>(() =>
    getAiCache(cacheKey)
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [open, setOpen] = useState(false);

  const handleExplain = async () => {
    if (explanation) {
      setOpen(!open);
      return;
    }

    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/ai/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...props, locale }),
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.error ?? "Failed to generate explanation");
        return;
      }

      setExplanation(data.explanation);
      setAiCache(cacheKey, data.explanation);
      setOpen(true);
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <button
        onClick={handleExplain}
        disabled={loading}
        className="text-xs px-2 py-1 rounded border border-purple-500/30 text-purple-400 hover:bg-purple-500/10 transition-colors disabled:opacity-50"
      >
        {loading ? (
          <span className="flex items-center gap-1">
            <span className="w-3 h-3 border border-purple-400 border-t-transparent rounded-full animate-spin" />
            {t("analyzing")}
          </span>
        ) : open ? (
          t("hideExplanation")
        ) : (
          t("explainWithAi")
        )}
      </button>

      {error && <p className="text-red-400 text-xs mt-1">{error}</p>}

      {open && explanation && (
        <div className="mt-3 p-3 bg-purple-500/5 border border-purple-500/20 rounded-lg">
          <div className="prose prose-invert prose-sm max-w-none text-gray-300 text-sm [&_h1]:text-base [&_h2]:text-sm [&_h3]:text-sm [&_strong]:text-purple-300">
            <MarkdownRenderer content={explanation} />
          </div>
        </div>
      )}
    </div>
  );
}

function MarkdownRenderer({ content }: { content: string }) {
  // Simple markdown → HTML conversion for common patterns
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
            className="bg-gray-950 rounded p-2 text-xs font-mono overflow-x-auto my-2"
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

    if (line.startsWith("### ")) {
      elements.push(
        <h3 key={i} className="font-semibold text-white mt-3 mb-1">
          {line.slice(4)}
        </h3>
      );
    } else if (line.startsWith("## ")) {
      elements.push(
        <h2 key={i} className="font-semibold text-white mt-3 mb-1">
          {line.slice(3)}
        </h2>
      );
    } else if (line.startsWith("# ")) {
      elements.push(
        <h1 key={i} className="font-bold text-white mt-3 mb-1">
          {line.slice(2)}
        </h1>
      );
    } else if (line.startsWith("- ") || line.startsWith("* ")) {
      elements.push(
        <li key={i} className="ml-4 list-disc">
          <InlineMarkdown text={line.slice(2)} />
        </li>
      );
    } else if (/^\d+\.\s/.test(line)) {
      const text = line.replace(/^\d+\.\s/, "");
      elements.push(
        <li key={i} className="ml-4 list-decimal">
          <InlineMarkdown text={text} />
        </li>
      );
    } else if (line.trim() === "") {
      elements.push(<br key={i} />);
    } else {
      elements.push(
        <p key={i} className="my-1">
          <InlineMarkdown text={line} />
        </p>
      );
    }
  }

  return <>{elements}</>;
}

function InlineMarkdown({ text }: { text: string }) {
  // Handle **bold**, `code`, and regular text
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return (
    <>
      {parts.map((part, i) => {
        if (part.startsWith("**") && part.endsWith("**")) {
          return (
            <strong key={i} className="text-purple-300">
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
