"use client";

import { useState } from "react";

interface Props {
  scanId: string;
  vulnId: string;
  ruleName: string;
  message: string;
  filePath: string;
  line: number;
  snippet: string | null;
  suggestion: string | null;
}

function getCacheKey(scanId: string, vulnId: string) {
  return `vexlit-ai-${scanId}-${vulnId}-fix`;
}

export function AiFixButton({ scanId, vulnId, ...props }: Props) {
  const cacheKey = getCacheKey(scanId, vulnId);
  const [fix, setFix] = useState<string | null>(() => {
    if (typeof window === "undefined") return null;
    return localStorage.getItem(cacheKey);
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  if (!props.snippet) return null;

  const handleFix = async () => {
    if (fix) {
      setOpen(!open);
      return;
    }

    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/ai/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(props),
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.error ?? "Failed to generate fix");
        return;
      }

      setFix(data.fix);
      localStorage.setItem(cacheKey, data.fix);
      setOpen(true);
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = async () => {
    if (!fix) return;
    // Extract code from markdown code blocks if present
    const codeMatch = fix.match(/```[\w]*\n([\s\S]*?)```/);
    const codeToCopy = codeMatch ? codeMatch[1].trim() : fix.trim();
    await navigator.clipboard.writeText(codeToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div>
      <button
        onClick={handleFix}
        disabled={loading}
        className="text-xs px-2 py-1 rounded border border-green-500/30 text-green-400 hover:bg-green-500/10 transition-colors disabled:opacity-50"
      >
        {loading ? (
          <span className="flex items-center gap-1">
            <span className="w-3 h-3 border border-green-400 border-t-transparent rounded-full animate-spin" />
            Generating...
          </span>
        ) : open ? (
          "Hide Fix"
        ) : (
          "Generate Fix"
        )}
      </button>

      {error && <p className="text-red-400 text-xs mt-1">{error}</p>}

      {open && fix && (
        <div className="mt-3 space-y-2">
          {/* Before */}
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs text-red-400 font-medium">Before</span>
            </div>
            <pre className="px-3 py-2 bg-red-500/5 border border-red-500/20 rounded text-sm font-mono text-gray-300 overflow-x-auto">
              {props.snippet}
            </pre>
          </div>

          {/* After */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-green-400 font-medium">After</span>
              <button
                onClick={handleCopy}
                className="text-xs px-2 py-0.5 rounded text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
              >
                {copied ? "Copied!" : "Copy"}
              </button>
            </div>
            <pre className="px-3 py-2 bg-green-500/5 border border-green-500/20 rounded text-sm font-mono text-gray-300 overflow-x-auto">
              {fix.replace(/^```[\w]*\n/, "").replace(/\n```$/, "")}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
