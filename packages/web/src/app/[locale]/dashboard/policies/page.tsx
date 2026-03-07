import { getTranslations } from "next-intl/server";
import { PoliciesClient } from "@/components/policies-client";

export default async function PoliciesPage() {
  const t = await getTranslations("policies");

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">{t("title")}</h1>
          <p className="text-gray-400 text-sm mt-1">{t("description")}</p>
        </div>
      </div>
      <PoliciesClient />
    </div>
  );
}
