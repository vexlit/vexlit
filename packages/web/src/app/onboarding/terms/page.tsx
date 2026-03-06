"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

const TERMS_VERSION = "v1.0";

export default function TermsPage() {
  const router = useRouter();
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [marketingAccepted, setMarketingAccepted] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleAccept = async () => {
    if (!termsAccepted) return;
    setLoading(true);

    try {
      const res = await fetch("/api/profile", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          terms_version: TERMS_VERSION,
          terms_accepted_at: new Date().toISOString(),
          marketing_consent: marketingAccepted,
        }),
      });

      if (res.ok) {
        router.push("/onboarding/setup");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center px-4">
      <div className="w-full max-w-2xl">
        <div className="text-center mb-8">
          <h1 className="text-2xl font-bold text-white">Welcome to VEXLIT</h1>
          <p className="text-gray-400 text-sm mt-2">
            Please review and accept our terms to continue
          </p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-6">
          {/* Terms of Service */}
          <section>
            <h2 className="text-white font-semibold mb-3">Terms of Service</h2>
            <div className="bg-gray-950 border border-gray-800 rounded-lg p-4 h-48 overflow-y-auto text-gray-400 text-sm space-y-3">
              <p>
                <strong className="text-gray-300">1. Code Access & Scanning</strong><br />
                VEXLIT scans your code repositories for security vulnerabilities using
                static analysis. We access only the files and branches you explicitly
                authorize. Scan results are stored securely and associated with your account.
              </p>
              <p>
                <strong className="text-gray-300">2. Data Processing</strong><br />
                Source code is processed in-memory during scanning and is not permanently
                stored beyond scan result metadata (file paths, line numbers, code snippets
                around vulnerabilities). Full source code is not retained after scan completion.
              </p>
              <p>
                <strong className="text-gray-300">3. AI Analysis Disclosure</strong><br />
                When you use AI-powered features (explanations, fix suggestions, reports),
                relevant code snippets may be sent to third-party AI providers (Anthropic)
                for processing. This data is not used for model training.
              </p>
              <p>
                <strong className="text-gray-300">4. Scan Result Retention</strong><br />
                Scan results (vulnerability metadata, severity ratings, suggestions) are
                retained for the lifetime of your account. You may delete projects and
                associated scan data at any time.
              </p>
              <p>
                <strong className="text-gray-300">5. Service Limitations</strong><br />
                VEXLIT provides automated security scanning as a supplementary tool.
                It does not replace professional security audits. Results may contain
                false positives or miss certain vulnerability types.
              </p>
            </div>
          </section>

          {/* Privacy Policy */}
          <section>
            <h2 className="text-white font-semibold mb-3">Privacy Policy</h2>
            <div className="bg-gray-950 border border-gray-800 rounded-lg p-4 h-36 overflow-y-auto text-gray-400 text-sm space-y-3">
              <p>
                <strong className="text-gray-300">Information We Collect</strong><br />
                GitHub profile information (username, email, avatar), repository metadata
                (names, branches), and scan results. We do not sell your data to third parties.
              </p>
              <p>
                <strong className="text-gray-300">How We Use Your Data</strong><br />
                To provide security scanning services, display scan results, generate
                reports, and send notifications about new vulnerabilities found in your code.
              </p>
              <p>
                <strong className="text-gray-300">Third-Party Services</strong><br />
                We use Supabase (database/auth), Vercel (hosting), and Anthropic (AI features).
                Each service has their own privacy policy governing data they process.
              </p>
            </div>
          </section>

          {/* Checkboxes */}
          <div className="space-y-3 pt-2">
            <label className="flex items-start gap-3 cursor-pointer group">
              <input
                type="checkbox"
                checked={termsAccepted}
                onChange={(e) => setTermsAccepted(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded border-gray-600 bg-gray-800 text-red-600 focus:ring-red-500"
              />
              <span className="text-sm text-gray-300 group-hover:text-white transition-colors">
                I agree to the Terms of Service and Privacy Policy{" "}
                <span className="text-red-400">(required)</span>
              </span>
            </label>
            <label className="flex items-start gap-3 cursor-pointer group">
              <input
                type="checkbox"
                checked={marketingAccepted}
                onChange={(e) => setMarketingAccepted(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded border-gray-600 bg-gray-800 text-red-600 focus:ring-red-500"
              />
              <span className="text-sm text-gray-400 group-hover:text-gray-300 transition-colors">
                I agree to receive product updates and security tips via email (optional)
              </span>
            </label>
          </div>

          {/* Submit */}
          <button
            onClick={handleAccept}
            disabled={!termsAccepted || loading}
            className="w-full py-3 bg-red-600 text-white rounded-lg font-medium hover:bg-red-700 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {loading ? "Processing..." : "Accept & Continue"}
          </button>
        </div>

        <p className="text-center text-gray-600 text-xs mt-4">
          Terms version {TERMS_VERSION}
        </p>
      </div>
    </div>
  );
}
