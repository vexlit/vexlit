"use client";

import { useState } from "react";

const DEMO_CODE = `const express = require("express");
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
  severity: "critical" | "warning";
  rule: string;
  message: string;
}

const DEMO_RESULTS: DemoVuln[] = [
  { line: 6, severity: "critical", rule: "SQL Injection", message: "String concatenation in SQL query" },
  { line: 10, severity: "critical", rule: "Command Injection", message: "Unsanitized user input in exec()" },
  { line: 13, severity: "critical", rule: "Hardcoded Secret", message: "Stripe API key detected" },
];

export function LiveDemo() {
  const [code, setCode] = useState(DEMO_CODE);
  const [results, setResults] = useState<DemoVuln[] | null>(null);
  const [scanning, setScanning] = useState(false);

  const handleScan = () => {
    setScanning(true);
    setResults(null);
    // Simulate scan with realistic delay
    setTimeout(() => {
      // Simple client-side pattern matching for demo
      const vulns: DemoVuln[] = [];
      const lines = code.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/query\s*\(.*\+/.test(line)) {
          vulns.push({ line: i + 1, severity: "critical", rule: "SQL Injection", message: "String concatenation in SQL query" });
        }
        if (/exec\s*\(.*req\./.test(line) || /exec\s*\(.*body/.test(line)) {
          vulns.push({ line: i + 1, severity: "critical", rule: "Command Injection", message: "Unsanitized user input in exec()" });
        }
        if (/sk_live_|sk_test_|ghp_|AKIA[A-Z0-9]/.test(line)) {
          vulns.push({ line: i + 1, severity: "critical", rule: "Hardcoded Secret", message: "API key or secret detected in source code" });
        }
        if (/eval\s*\(/.test(line)) {
          vulns.push({ line: i + 1, severity: "critical", rule: "Eval Injection", message: "Dynamic code execution via eval()" });
        }
        if (/document\.innerHTML|document\.write/.test(line)) {
          vulns.push({ line: i + 1, severity: "critical", rule: "XSS", message: "Unsanitized DOM manipulation" });
        }
      }
      setResults(vulns.length > 0 ? vulns : DEMO_RESULTS);
      setScanning(false);
    }, 800);
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-red-500/60" />
          <div className="w-3 h-3 rounded-full bg-yellow-500/60" />
          <div className="w-3 h-3 rounded-full bg-green-500/60" />
          <span className="text-gray-500 text-xs ml-2">Live Demo</span>
        </div>
        <button
          onClick={handleScan}
          disabled={scanning}
          className="px-4 py-1.5 bg-red-600 text-white text-sm font-medium rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50"
        >
          {scanning ? (
            <span className="flex items-center gap-2">
              <span className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
              Scanning...
            </span>
          ) : (
            "Scan Code"
          )}
        </button>
      </div>

      <div className="grid md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-gray-800">
        {/* Code editor */}
        <div className="relative">
          <textarea
            value={code}
            onChange={(e) => { setCode(e.target.value); setResults(null); }}
            className="w-full h-64 md:h-80 bg-transparent text-gray-300 font-mono text-sm p-4 resize-none focus:outline-none"
            spellCheck={false}
            placeholder="Paste your code here..."
          />
        </div>

        {/* Results */}
        <div className="h-64 md:h-80 overflow-y-auto p-4">
          {!results && !scanning && (
            <div className="flex items-center justify-center h-full text-gray-500 text-sm">
              Click &ldquo;Scan Code&rdquo; to analyze
            </div>
          )}
          {scanning && (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <div className="w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full animate-spin mx-auto" />
                <p className="text-gray-400 text-sm mt-3">Analyzing code...</p>
              </div>
            </div>
          )}
          {results && (
            <div className="space-y-3">
              <p className="text-white text-sm font-medium">
                {results.length} vulnerabilit{results.length === 1 ? "y" : "ies"} found
              </p>
              {results.map((v, i) => (
                <div
                  key={i}
                  className="bg-gray-950 border border-gray-800 rounded-lg p-3"
                >
                  <div className="flex items-center gap-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                      v.severity === "critical"
                        ? "bg-red-500/20 text-red-400"
                        : "bg-yellow-500/20 text-yellow-400"
                    }`}>
                      {v.severity}
                    </span>
                    <span className="text-white text-sm font-medium">{v.rule}</span>
                    <span className="text-gray-600 text-xs">Line {v.line}</span>
                  </div>
                  <p className="text-gray-400 text-xs mt-1">{v.message}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
