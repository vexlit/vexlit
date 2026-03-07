"use client";

import { useState, useRef } from "react";
import { useTranslations } from "next-intl";

/* ─── Example presets with vulnerable + fixed code ─── */

interface Preset {
  label: string;
  code: string;
  fixed: string;
}

const PRESETS: Preset[] = [
  {
    label: "SQL Injection",
    code: `const express = require("express");
const app = express();

app.get("/users", (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id = " + id);
});`,
    fixed: `const express = require("express");
const app = express();

app.get("/users", (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id = ?", [id]);
});`,
  },
  {
    label: "XSS",
    code: `function Comment({ text }) {
  return (
    <div
      dangerouslySetInnerHTML={{
        __html: text
      }}
    />
  );
}`,
    fixed: `import DOMPurify from "dompurify";

function Comment({ text }) {
  return (
    <div>
      {DOMPurify.sanitize(text)}
    </div>
  );
}`,
  },
  {
    label: "Hardcoded Secret",
    code: `const config = {
  jwtSecret: "sk_live_a1b2c3d4e5f6",
  apiKey: "AKIAIOSFODNN7EXAMPLE",
  dbPassword: "admin123!",
};`,
    fixed: `const config = {
  jwtSecret: process.env.JWT_SECRET,
  apiKey: process.env.API_KEY,
  dbPassword: process.env.DB_PASSWORD,
};`,
  },
  {
    label: "Command Injection",
    code: `const express = require("express");
const { exec } = require("child_process");
const app = express();

app.post("/deploy", (req, res) => {
  exec(req.body.command);
});`,
    fixed: `const express = require("express");
const { execFile } = require("child_process");
const app = express();

app.post("/deploy", (req, res) => {
  const allowed = ["deploy", "build", "test"];
  if (!allowed.includes(req.body.command)) {
    return res.status(400).json({ error: "Invalid command" });
  }
  execFile("scripts/" + req.body.command + ".sh");
});`,
  },
];

const DEFAULT_CODE = `const express = require("express");
const app = express();

app.get("/users", (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id = " + id);
});

app.post("/deploy", (req, res) => {
  exec(req.body.command);
});

const API_KEY = "sk_live_51HxGz2CjpKJds9sK3n";
`;

interface DemoVuln {
  line: number;
  severity: "critical" | "warning" | "info";
  rule: string;
  message: string;
  confidence?: string;
  cwe?: string;
  suggestion?: string;
}

function detectLanguage(code: string): "javascript" | "typescript" | "python" {
  const trimmed = code.trimStart();
  if (
    trimmed.startsWith("import ") && !trimmed.startsWith("import {") && !trimmed.startsWith("import '") && !trimmed.startsWith("import \"") ||
    trimmed.startsWith("from ") ||
    /\bdef\s+\w+\s*\(/.test(trimmed) ||
    /\bclass\s+\w+.*:/.test(trimmed) ||
    trimmed.includes("print(")
  ) {
    return "python";
  }
  if (/:\s*(string|number|boolean|void)\b/.test(code) || /interface\s+\w+/.test(code)) {
    return "typescript";
  }
  return "javascript";
}

// Client-side quick scan patterns (instant, ~5 rules)
function quickScan(code: string): DemoVuln[] {
  const vulns: DemoVuln[] = [];
  const lines = code.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/query\s*\(.*\+/.test(line) || /query\s*\(\s*`[^`]*\$\{/.test(line)) {
      vulns.push({ line: i + 1, severity: "critical", rule: "SQL Injection", message: "String concatenation in SQL query", cwe: "CWE-89" });
    }
    if (/exec\s*\(.*req\./.test(line) || /exec\s*\(.*body/.test(line)) {
      vulns.push({ line: i + 1, severity: "critical", rule: "Command Injection", message: "Unsanitized user input in exec()", cwe: "CWE-78" });
    }
    if (/sk_live_|sk_test_|ghp_|AKIA[A-Z0-9]/.test(line)) {
      vulns.push({ line: i + 1, severity: "critical", rule: "Hardcoded Secret", message: "API key or secret detected in source code", cwe: "CWE-798" });
    }
    if (/eval\s*\(/.test(line)) {
      vulns.push({ line: i + 1, severity: "critical", rule: "Eval Injection", message: "Dynamic code execution via eval()", cwe: "CWE-95" });
    }
    if (/\.innerHTML\s*=|document\.write/.test(line)) {
      vulns.push({ line: i + 1, severity: "warning", rule: "Cross-Site Scripting (XSS)", message: "Unsanitized DOM manipulation", cwe: "CWE-79" });
    }
    if (/dangerouslySetInnerHTML/.test(line)) {
      vulns.push({ line: i + 1, severity: "warning", rule: "Cross-Site Scripting (XSS)", message: "dangerouslySetInnerHTML — potential XSS vector", cwe: "CWE-79" });
    }
  }
  // Multiline template literal SQL injection
  const sqlTplRe = /query\s*\(\s*`[\s\S]*?\$\{[\s\S]*?`\s*\)/g;
  let m: RegExpExecArray | null;
  while ((m = sqlTplRe.exec(code)) !== null) {
    const lineNum = code.slice(0, m.index).split("\n").length;
    if (!vulns.some((v) => v.rule === "SQL Injection" && v.line === lineNum)) {
      vulns.push({ line: lineNum, severity: "critical", rule: "SQL Injection", message: "Template literal with interpolation in SQL query", cwe: "CWE-89" });
    }
  }
  return vulns;
}

export function LiveDemo() {
  const t = useTranslations("liveDemo");
  const [code, setCode] = useState(DEFAULT_CODE);
  const [quickResults, setQuickResults] = useState<DemoVuln[] | null>(null);
  const [fullResults, setFullResults] = useState<DemoVuln[] | null>(null);
  const [scanning, setScanning] = useState(false);
  const [fullScanning, setFullScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [showFix, setShowFix] = useState(false);
  const [activePreset, setActivePreset] = useState<number | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const handlePreset = (index: number) => {
    setActivePreset(index);
    setCode(PRESETS[index].code);
    setQuickResults(null);
    setFullResults(null);
    setScanError(null);
    setShowFix(false);
  };

  const handleScan = async () => {
    abortRef.current?.abort();
    setScanning(true);
    setQuickResults(null);
    setFullResults(null);
    setScanError(null);
    setShowFix(false);

    // Phase 1: instant client-side scan
    setTimeout(() => {
      const quick = quickScan(code);
      setQuickResults(quick);
      setScanning(false);
    }, 300);

    // Phase 2: real engine scan (parallel)
    setFullScanning(true);
    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const res = await fetch("/api/scan/demo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, language: detectLanguage(code) }),
        signal: controller.signal,
      });

      const data = await res.json();
      if (!controller.signal.aborted) {
        if (res.ok && data.vulnerabilities) {
          setFullResults(data.vulnerabilities);
          // Auto-open fix panel when full engine completes (preset selected)
          if (data.vulnerabilities.length > 0) {
            setShowFix(true);
          }
        } else if (res.status === 429) {
          setScanError(t("tooManyRequests"));
        } else {
          setScanError(t("fullScanUnavailable"));
        }
      }
    } catch (err) {
      if (err instanceof Error && err.name !== "AbortError") {
        setScanError(t("fullScanUnavailable"));
      }
    } finally {
      setFullScanning(false);
    }
  };

  const displayResults = fullResults ?? quickResults;
  const isFullEngine = fullResults !== null;
  const currentPreset = activePreset !== null ? PRESETS[activePreset] : null;

  return (
    <div className="space-y-4">
      {/* Example preset buttons */}
      <div className="flex flex-wrap gap-2 justify-center">
        <span className="text-gray-500 text-sm self-center mr-1">{t("tryExample")}</span>
        {PRESETS.map((preset, i) => (
          <button
            key={preset.label}
            onClick={() => handlePreset(i)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activePreset === i
                ? "bg-red-600 text-white"
                : "bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700"
            }`}
          >
            {preset.label}
          </button>
        ))}
      </div>

      {/* Main editor + results panel */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500/60" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/60" />
            <div className="w-3 h-3 rounded-full bg-green-500/60" />
            <span className="text-gray-500 text-xs ml-2">{t("liveDemoLabel")}</span>
          </div>
          <button
            onClick={handleScan}
            disabled={scanning}
            className="px-4 py-1.5 bg-red-600 text-white text-sm font-medium rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50"
          >
            {scanning ? (
              <span className="flex items-center gap-2">
                <span className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                {t("scanning")}
              </span>
            ) : (
              t("scanButton")
            )}
          </button>
        </div>

        <div className="grid md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-gray-800">
          {/* Code editor */}
          <div className="relative">
            <textarea
              value={code}
              onChange={(e) => { setCode(e.target.value); setQuickResults(null); setFullResults(null); setScanError(null); setShowFix(false); setActivePreset(null); }}
              className="w-full h-64 md:h-80 bg-transparent text-gray-300 font-mono text-sm p-4 resize-none focus:outline-none"
              spellCheck={false}
              aria-label={t("pasteCodeHere")}
              placeholder={t("pasteCodeHere")}
            />
          </div>

          {/* Results */}
          <div className="h-64 md:h-80 overflow-y-auto p-4">
            {!displayResults && !scanning && (
              <div className="flex items-center justify-center h-full text-gray-500 text-sm">
                {t("clickScanCode")}
              </div>
            )}
            {scanning && !displayResults && (
              <div className="flex items-center justify-center h-full">
                <div className="text-center">
                  <div className="w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full animate-spin mx-auto" />
                  <p className="text-gray-400 text-sm mt-3">{t("analyzingCode")}</p>
                </div>
              </div>
            )}
            {displayResults && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <p className="text-white text-sm font-medium">
                    {t("vulnsFound", { count: displayResults.length })}
                  </p>
                  {isFullEngine ? (
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-green-500/15 text-green-400 font-medium">
                      {t("fullEngine")}
                    </span>
                  ) : fullScanning ? (
                    <span className="flex items-center gap-1.5 text-[10px] px-2 py-0.5 rounded-full bg-yellow-500/15 text-yellow-400 font-medium">
                      <span className="w-2 h-2 border border-yellow-400 border-t-transparent rounded-full animate-spin" />
                      {t("deepScanning")}
                    </span>
                  ) : (
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-gray-700/50 text-gray-400 font-medium">
                      {t("quickScan")}
                    </span>
                  )}
                </div>
                {scanError && (
                  <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg px-3 py-2 text-yellow-400 text-xs">
                    {scanError}
                  </div>
                )}
                {displayResults.map((v, i) => (
                  <div
                    key={i}
                    className="bg-gray-950 border border-gray-800 rounded-lg p-3"
                  >
                    <div className="flex items-center gap-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                        v.severity === "critical"
                          ? "bg-red-500/20 text-red-400"
                          : v.severity === "warning"
                          ? "bg-yellow-500/20 text-yellow-400"
                          : "bg-blue-500/20 text-blue-400"
                      }`}>
                        {v.severity}
                      </span>
                      <span className="text-white text-sm font-medium">{v.rule}</span>
                      <span className="text-gray-600 text-xs">Line {v.line}</span>
                    </div>
                    <p className="text-gray-400 text-xs mt-1">{v.message}</p>
                    {isFullEngine && v.cwe && (
                      <p className="text-gray-600 text-[10px] mt-1">{v.cwe}</p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Auto-fix diff section — only when preset is selected and results exist */}
      {displayResults && displayResults.length > 0 && currentPreset && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <button
            onClick={() => setShowFix(!showFix)}
            className="w-full flex items-center justify-between px-4 py-3 border-b border-gray-800 hover:bg-gray-800/50 transition-colors"
          >
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-green-500" />
              <span className="text-green-400 text-sm font-medium">{t("suggestedFix")}</span>
              <span className="text-gray-500 text-xs">{t("aiSuggestedPatch")}</span>
            </div>
            <svg
              className={`w-4 h-4 text-gray-500 transition-transform ${showFix ? "rotate-180" : ""}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>

          {showFix && (
            <div className="grid md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-gray-800">
              {/* Vulnerable (before) */}
              <div>
                <div className="flex items-center gap-2 px-4 py-2 bg-red-500/5 border-b border-red-500/10">
                  <span className="w-2 h-2 rounded-full bg-red-500" />
                  <span className="text-red-400 text-xs font-medium">{t("vulnerable")}</span>
                </div>
                <pre className="p-4 text-sm text-gray-300 overflow-x-auto leading-relaxed font-mono">
                  <code>{currentPreset.code}</code>
                </pre>
              </div>

              {/* Fixed (after) */}
              <div>
                <div className="flex items-center gap-2 px-4 py-2 bg-green-500/5 border-b border-green-500/10">
                  <span className="w-2 h-2 rounded-full bg-green-500" />
                  <span className="text-green-400 text-xs font-medium">{t("fixed")}</span>
                </div>
                <pre className="p-4 text-sm text-gray-300 overflow-x-auto leading-relaxed font-mono">
                  <code>{currentPreset.fixed}</code>
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
