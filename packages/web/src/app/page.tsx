import Link from "next/link";

const RULES_PREVIEW = [
  { id: "VEXLIT-001", name: "Hardcoded Secrets", severity: "critical" },
  { id: "VEXLIT-002", name: "SQL Injection", severity: "critical" },
  { id: "VEXLIT-003", name: "XSS", severity: "critical" },
  { id: "VEXLIT-011", name: "NoSQL Injection", severity: "critical" },
  { id: "VEXLIT-021", name: "Path Traversal", severity: "critical" },
  { id: "VEXLIT-022", name: "Command Injection", severity: "critical" },
  { id: "VEXLIT-007", name: "JWT Hardcoded Secret", severity: "critical" },
  { id: "VEXLIT-012", name: "SSRF", severity: "warning" },
  { id: "VEXLIT-018", name: "Timing Attack", severity: "warning" },
];

export default function HomePage() {
  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Nav */}
      <nav className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
        <span className="text-xl font-bold">VEXLIT</span>
        <div className="flex gap-4 items-center">
          <Link href="/login" className="text-gray-400 hover:text-white text-sm">
            Sign in
          </Link>
          <Link
            href="/login"
            className="px-4 py-2 bg-red-600 rounded-lg text-sm font-medium hover:bg-red-700"
          >
            Get Started
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <section className="max-w-4xl mx-auto px-6 pt-24 pb-16 text-center">
        <h1 className="text-5xl md:text-6xl font-bold leading-tight">
          Find security vulnerabilities
          <br />
          <span className="text-red-500">before attackers do</span>
        </h1>
        <p className="mt-6 text-xl text-gray-400 max-w-2xl mx-auto">
          AI-powered static analysis with AST-based detection. 21 security rules
          covering OWASP Top 10 and CWE. SARIF output for GitHub integration.
        </p>
        <div className="mt-8 flex gap-4 justify-center">
          <Link
            href="/login"
            className="px-8 py-3 bg-red-600 rounded-lg font-medium hover:bg-red-700 transition-colors"
          >
            Start Scanning
          </Link>
          <a
            href="https://github.com/vexlit/vexlit"
            target="_blank"
            rel="noopener noreferrer"
            className="px-8 py-3 border border-gray-700 rounded-lg font-medium hover:border-gray-500 transition-colors"
          >
            View on GitHub
          </a>
        </div>
      </section>

      {/* Code example */}
      <section className="max-w-3xl mx-auto px-6 pb-16">
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="px-4 py-2 border-b border-gray-800 flex gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500/50" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/50" />
            <div className="w-3 h-3 rounded-full bg-green-500/50" />
            <span className="text-gray-500 text-xs ml-2">Terminal</span>
          </div>
          <pre className="p-4 text-sm font-mono text-gray-300 overflow-x-auto">
            <span className="text-gray-500">$</span> npx @vexlit/cli scan
            ./src{"\n\n"}
            <span className="text-white font-bold">VEXLIT Scan Results</span>
            {"\n"}
            Files scanned: 12{"\n"}
            Vulnerabilities:{" "}
            <span className="text-red-400">3 critical</span>,{" "}
            <span className="text-yellow-400">2 warning</span>,{" "}
            <span className="text-blue-400">1 info</span>
            {"\n\n"}
            <span className="text-white font-bold">src/auth.ts</span>
            {"\n"}
            {"  "}
            <span className="text-red-400">[CRITICAL]</span> Line 15:7
            Hardcoded password{"\n"}
            {"    "}
            <span className="text-gray-500">
              const password = &quot;admin123&quot;;
            </span>
            {"\n"}
            {"    "}
            <span className="text-green-400/80">
              Fix: Move secrets to environment variables
            </span>
          </pre>
        </div>
      </section>

      {/* Features */}
      <section className="max-w-7xl mx-auto px-6 py-16 border-t border-gray-800">
        <h2 className="text-3xl font-bold text-center mb-12">
          Why VEXLIT?
        </h2>
        <div className="grid md:grid-cols-3 gap-8">
          <FeatureCard
            title="AST-Based Analysis"
            description="Hybrid regex + AST scanning for JavaScript and TypeScript reduces false positives by understanding code structure."
          />
          <FeatureCard
            title="21 Security Rules"
            description="Covers OWASP Top 10 including SQL Injection, XSS, SSRF, Command Injection, Path Traversal, and more."
          />
          <FeatureCard
            title="GitHub Integration"
            description="SARIF output for GitHub Code Scanning. GitHub Action for CI/CD. Results appear in the Security tab."
          />
          <FeatureCard
            title="AI Verification"
            description="Optional Claude AI secondary analysis filters out false positives and adjusts severity levels."
          />
          <FeatureCard
            title="Scan History"
            description="Track vulnerability trends over time. See how your security posture improves with each commit."
          />
          <FeatureCard
            title="Free & Open Source"
            description="CLI and core engine are open source. Use locally, in CI/CD, or through the web dashboard."
          />
        </div>
      </section>

      {/* Rules preview */}
      <section className="max-w-4xl mx-auto px-6 py-16 border-t border-gray-800">
        <h2 className="text-3xl font-bold text-center mb-8">Security Rules</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {RULES_PREVIEW.map((rule) => (
            <div
              key={rule.id}
              className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 flex items-center gap-3"
            >
              <span
                className={`w-2 h-2 rounded-full ${rule.severity === "critical" ? "bg-red-500" : "bg-yellow-500"}`}
              />
              <div>
                <p className="text-white text-sm">{rule.name}</p>
                <p className="text-gray-600 text-xs">{rule.id}</p>
              </div>
            </div>
          ))}
        </div>
        <p className="text-center text-gray-500 text-sm mt-4">
          + 12 more rules
        </p>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-800 py-8">
        <div className="max-w-7xl mx-auto px-6 flex justify-between items-center">
          <span className="text-gray-600 text-sm">VEXLIT</span>
          <a
            href="https://github.com/vexlit/vexlit"
            target="_blank"
            rel="noopener noreferrer"
            className="text-gray-600 hover:text-gray-400 text-sm"
          >
            GitHub
          </a>
        </div>
      </footer>
    </div>
  );
}

function FeatureCard({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
      <h3 className="text-white font-semibold mb-2">{title}</h3>
      <p className="text-gray-400 text-sm leading-relaxed">{description}</p>
    </div>
  );
}
