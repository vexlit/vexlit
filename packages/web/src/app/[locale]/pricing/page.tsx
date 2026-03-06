import { getTranslations } from "next-intl/server";
import { PricingClient } from "@/components/pricing/pricing-client";
import { LandingNav } from "@/components/landing/landing-nav";

export default async function PricingPage() {
  const t = await getTranslations("pricing");

  const plans = {
    free: {
      name: t("free.name"),
      price: t("free.price"),
      period: t("free.period"),
      description: t("free.description"),
      cta: t("free.cta"),
      features: Object.values(t.raw("free.features")) as string[],
    },
    pro: {
      name: t("pro.name"),
      price: t("pro.price"),
      period: t("pro.period"),
      yearlyPrice: t("pro.yearlyPrice"),
      description: t("pro.description"),
      cta: t("pro.cta"),
      badge: t("pro.badge"),
      features: Object.values(t.raw("pro.features")) as string[],
    },
    team: {
      name: t("team.name"),
      price: t("team.price"),
      period: t("team.period"),
      yearlyPrice: t("team.yearlyPrice"),
      description: t("team.description"),
      cta: t("team.cta"),
      features: Object.values(t.raw("team.features")) as string[],
    },
  };

  const faq = Object.values(t.raw("faq")) as { q: string; a: string }[];

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      <LandingNav />
      <PricingClient
        title={t("title")}
        subtitle={t("subtitle")}
        monthly={t("monthly")}
        yearly={t("yearly")}
        yearlyDiscount={t("yearlyDiscount")}
        plans={plans}
        faqTitle={t("faqTitle")}
        faq={faq}
        ctaTitle={t("ctaTitle")}
        ctaDescription={t("ctaDescription")}
        ctaButton={t("ctaButton")}
        comingSoonBadge={t("comingSoonBadge")}
      />
    </div>
  );
}
