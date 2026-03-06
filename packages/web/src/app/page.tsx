import Link from "next/link";
import { LandingClient } from "@/components/landing/landing-client";
import { LandingNavActions } from "@/components/landing/landing-nav-actions";

const RULES_PREVIEW = [
  { id: "VEXLIT-001", name: "Hardcoded Secrets", severity: "critical" },
  { id: "VEXLIT-002", name: "SQL Injection", severity: "critical" },
  { id: "VEXLIT-003", name: "XSS", severity: "critical" },
  { id: "VEXLIT-010", name: "Prototype Pollution", severity: "critical" },
  { id: "VEXLIT-011", name: "NoSQL Injection", severity: "critical" },
  { id: "VEXLIT-021", name: "Path Traversal", severity: "critical" },
  { id: "VEXLIT-022", name: "Command Injection", severity: "critical" },
  { id: "VEXLIT-007", name: "JWT Hardcoded Secret", severity: "critical" },
  { id: "VEXLIT-012", name: "SSRF", severity: "warning" },
  { id: "VEXLIT-018", name: "Timing Attack", severity: "warning" },
  { id: "VEXLIT-020", name: "Unsafe Deserialization", severity: "critical" },
  { id: "VEXLIT-023", name: "Eval Injection", severity: "critical" },
];

const FEATURES = [
  {
    title: "AST-Based Analysis",
    description:
      "Hybrid regex + AST scanning with tree-sitter for JavaScript, TypeScript, and Python reduces false positives by understanding code structure.",
    icon: "tree",
  },
  {
    title: "263 Security Rules",
    description:
      "Covers OWASP Top 10 including SQL Injection, XSS, SSRF, Command Injection, Prototype Pollution, and 200+ secret patterns.",
    icon: "shield",
  },
  {
    title: "GitHub Integration",
    description:
      "One-click repo scanning. SARIF output for GitHub Code Scanning. Results appear directly in your Security tab.",
    icon: "github",
  },
  {
    title: "AI Verification",
    description:
      "Claude AI secondary analysis filters false positives, explains vulnerabilities in detail, and suggests code fixes.",
    icon: "ai",
  },
  {
    title: "Scan History & Trends",
    description:
      "Track vulnerability trends over time with visual charts. See your security posture improve with each commit.",
    icon: "chart",
  },
  {
    title: "Free & Open Source",
    description:
      "CLI and core engine are open source. Use locally, in CI/CD, or through the web dashboard. MIT licensed.",
    icon: "open",
  },
];

export default function HomePage() {
  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Nav */}
      <nav className="fixed top-0 w-full z-50 border-b border-gray-800 bg-gray-950/80 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
          <Link href="/" className="text-xl font-bold text-white">
            VEXLIT
          </Link>
          <LandingNavActions />
        </div>
      </nav>

      <LandingClient
        rules={RULES_PREVIEW}
        features={FEATURES}
      />

      {/* Footer */}
      <footer className="border-t border-gray-800 py-8">
        <div className="max-w-7xl mx-auto px-6 flex flex-col sm:flex-row justify-between items-center gap-4">
          <span className="text-gray-600 text-sm">
            VEXLIT &mdash; AI-Powered Security Scanner
          </span>
          <div className="flex gap-6">
            <a
              href="https://github.com/vexlit/vexlit"
              target="_blank"
              rel="noopener noreferrer"
              className="text-gray-600 hover:text-gray-400 text-sm transition-colors"
            >
              GitHub
            </a>
            <Link
              href="/login"
              className="text-gray-600 hover:text-gray-400 text-sm transition-colors"
            >
              Dashboard
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
