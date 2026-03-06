"use client";

import { useState } from "react";
import { useRouter } from "@/i18n/navigation";
import { useTranslations } from "next-intl";

const TERMS_VERSION = "v1.0";

export default function TermsPage() {
  const router = useRouter();
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [marketingAccepted, setMarketingAccepted] = useState(false);
  const [loading, setLoading] = useState(false);
  const t = useTranslations("onboarding");
  const tTerms = useTranslations("terms");
  const tPrivacy = useTranslations("privacy");

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
          <h1 className="text-2xl font-bold text-white">{t("welcomeTitle")}</h1>
          <p className="text-gray-400 text-sm mt-2">{t("welcomeSubtitle")}</p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-6">
          <section>
            <h2 className="text-white font-semibold mb-3">{t("termsTitle")}</h2>
            <div className="bg-gray-950 border border-gray-800 rounded-lg p-4 h-48 overflow-y-auto text-gray-400 text-sm space-y-3">
              <p><strong className="text-gray-300">{tTerms("codeAccess")}</strong><br />{tTerms("codeAccessDesc")}</p>
              <p><strong className="text-gray-300">{tTerms("dataProcessing")}</strong><br />{tTerms("dataProcessingDesc")}</p>
              <p><strong className="text-gray-300">{tTerms("aiDisclosure")}</strong><br />{tTerms("aiDisclosureDesc")}</p>
              <p><strong className="text-gray-300">{tTerms("retention")}</strong><br />{tTerms("retentionDesc")}</p>
              <p><strong className="text-gray-300">{tTerms("limitations")}</strong><br />{tTerms("limitationsDesc")}</p>
            </div>
          </section>

          <section>
            <h2 className="text-white font-semibold mb-3">{t("privacyTitle")}</h2>
            <div className="bg-gray-950 border border-gray-800 rounded-lg p-4 h-36 overflow-y-auto text-gray-400 text-sm space-y-3">
              <p><strong className="text-gray-300">{tPrivacy("infoCollect")}</strong><br />{tPrivacy("infoCollectDesc")}</p>
              <p><strong className="text-gray-300">{tPrivacy("howWeUse")}</strong><br />{tPrivacy("howWeUseDesc")}</p>
              <p><strong className="text-gray-300">{tPrivacy("thirdParty")}</strong><br />{tPrivacy("thirdPartyDesc")}</p>
            </div>
          </section>

          <div className="space-y-3 pt-2">
            <label className="flex items-start gap-3 cursor-pointer group">
              <input type="checkbox" checked={termsAccepted} onChange={(e) => setTermsAccepted(e.target.checked)} className="mt-0.5 w-4 h-4 rounded border-gray-600 bg-gray-800 text-red-600 focus:ring-red-500" />
              <span className="text-sm text-gray-300 group-hover:text-white transition-colors">
                {t("termsAgree")} <span className="text-red-400">{t("required")}</span>
              </span>
            </label>
            <label className="flex items-start gap-3 cursor-pointer group">
              <input type="checkbox" checked={marketingAccepted} onChange={(e) => setMarketingAccepted(e.target.checked)} className="mt-0.5 w-4 h-4 rounded border-gray-600 bg-gray-800 text-red-600 focus:ring-red-500" />
              <span className="text-sm text-gray-400 group-hover:text-gray-300 transition-colors">{t("marketingAgree")}</span>
            </label>
          </div>

          <button onClick={handleAccept} disabled={!termsAccepted || loading} className="w-full py-3 bg-red-600 text-white rounded-lg font-medium hover:bg-red-700 transition-all disabled:opacity-40 disabled:cursor-not-allowed">
            {loading ? t("processing") : t("acceptContinue")}
          </button>
        </div>

        <p className="text-center text-gray-600 text-xs mt-4">
          {t("termsVersion")} {TERMS_VERSION}
        </p>
      </div>
    </div>
  );
}
