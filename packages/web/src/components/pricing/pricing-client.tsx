"use client";

import { Link } from "@/i18n/navigation";
import { useState, useEffect } from "react";
import { createSupabaseBrowser } from "@/lib/supabase-browser";

interface Plan {
  name: string;
  price: string;
  period: string;
  yearlyPrice?: string;
  description: string;
  cta: string;
  badge?: string;
  features: string[];
}

interface PricingClientProps {
  title: string;
  subtitle: string;
  monthly: string;
  yearly: string;
  yearlyDiscount: string;
  plans: { free: Plan; pro: Plan; team: Plan };
  faqTitle: string;
  faq: { q: string; a: string }[];
  ctaTitle: string;
  ctaDescription: string;
  ctaButton: string;
  comingSoonBadge: string;
}

const CHECK_ICON = (
  <svg className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
  </svg>
);

export function PricingClient({
  title,
  subtitle,
  monthly,
  yearly,
  yearlyDiscount,
  plans,
  faqTitle,
  faq,
  ctaTitle,
  ctaDescription,
  ctaButton,
  comingSoonBadge,
}: PricingClientProps) {
  const [isYearly, setIsYearly] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [openFaq, setOpenFaq] = useState<number | null>(null);

  useEffect(() => {
    const supabase = createSupabaseBrowser();
    supabase.auth.getSession().then(({ data: { session } }) => {
      setIsLoggedIn(!!session);
    });
  }, []);

  const ctaHref = isLoggedIn ? "/dashboard" : "/login";

  function getPrice(plan: Plan) {
    if (!plan.yearlyPrice) return plan.price;
    return isYearly ? plan.yearlyPrice : plan.price;
  }

  function getPeriod(plan: Plan) {
    if (!plan.yearlyPrice) return plan.period;
    return plan.period;
  }

  return (
    <>
      {/* Header */}
      <section className="max-w-4xl mx-auto px-6 pt-32 pb-12 text-center">
        <h1 className="text-4xl md:text-5xl font-bold tracking-tight">
          {title}
        </h1>
        <p className="mt-4 text-lg text-gray-400 max-w-2xl mx-auto">
          {subtitle}
        </p>

        {/* Billing toggle */}
        <div className="mt-8 inline-flex items-center gap-3 bg-gray-900 border border-gray-800 rounded-full p-1">
          <button
            onClick={() => setIsYearly(false)}
            className={`px-5 py-2 rounded-full text-sm font-medium transition-all ${
              !isYearly
                ? "bg-white text-gray-900"
                : "text-gray-400 hover:text-white"
            }`}
          >
            {monthly}
          </button>
          <button
            onClick={() => setIsYearly(true)}
            className={`px-5 py-2 rounded-full text-sm font-medium transition-all flex items-center gap-2 ${
              isYearly
                ? "bg-white text-gray-900"
                : "text-gray-400 hover:text-white"
            }`}
          >
            {yearly}
            <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-400 font-semibold">
              {yearlyDiscount}
            </span>
          </button>
        </div>
      </section>

      {/* Plan Cards */}
      <section className="max-w-6xl mx-auto px-6 pb-20">
        <div className="grid md:grid-cols-3 gap-6 items-start">
          {/* Free */}
          <PlanCard
            plan={plans.free}
            price={plans.free.price}
            period={plans.free.period}
            ctaHref={ctaHref}
            comingSoonBadge={comingSoonBadge}
          />

          {/* Pro (highlighted) */}
          <PlanCard
            plan={plans.pro}
            price={getPrice(plans.pro)}
            period={getPeriod(plans.pro)}
            highlighted
            ctaHref={ctaHref}
            comingSoonBadge={comingSoonBadge}
          />

          {/* Team */}
          <PlanCard
            plan={plans.team}
            price={getPrice(plans.team)}
            period={getPeriod(plans.team)}
            ctaHref={ctaHref}
            comingSoonBadge={comingSoonBadge}
          />
        </div>
      </section>

      {/* FAQ */}
      <section className="max-w-3xl mx-auto px-6 pb-20">
        <h2 className="text-2xl md:text-3xl font-bold text-center mb-10">
          {faqTitle}
        </h2>
        <div className="space-y-3">
          {faq.map((item, i) => (
            <div
              key={i}
              className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
            >
              <button
                onClick={() => setOpenFaq(openFaq === i ? null : i)}
                className="w-full flex items-center justify-between px-6 py-4 text-left"
              >
                <span className="text-white font-medium text-sm pr-4">{item.q}</span>
                <svg
                  className={`w-5 h-5 text-gray-400 flex-shrink-0 transition-transform ${
                    openFaq === i ? "rotate-180" : ""
                  }`}
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={2}
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
                </svg>
              </button>
              {openFaq === i && (
                <div className="px-6 pb-4">
                  <p className="text-gray-400 text-sm leading-relaxed">{item.a}</p>
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* Bottom CTA */}
      <section className="max-w-4xl mx-auto px-6 pb-20">
        <div className="bg-gradient-to-br from-red-500/10 to-orange-500/10 border border-red-500/20 rounded-2xl p-8 md:p-12 text-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">
            {ctaTitle}
          </h2>
          <p className="text-gray-400 max-w-lg mx-auto mb-8">
            {ctaDescription}
          </p>
          <Link
            href={ctaHref}
            className="inline-block px-8 py-3 bg-red-600 rounded-lg font-medium hover:bg-red-700 transition-all hover:shadow-lg hover:shadow-red-600/20"
          >
            {ctaButton}
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-800 py-8">
        <div className="max-w-7xl mx-auto px-6 flex flex-col sm:flex-row justify-between items-center gap-4">
          <span className="text-gray-600 text-sm">
            VEXLIT — AI-Powered Security Scanner
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
              href="/"
              className="text-gray-600 hover:text-gray-400 text-sm transition-colors"
            >
              Home
            </Link>
          </div>
        </div>
      </footer>
    </>
  );
}

function PlanCard({
  plan,
  price,
  period,
  highlighted,
  ctaHref,
  comingSoonBadge,
}: {
  plan: Plan;
  price: string;
  period: string;
  highlighted?: boolean;
  ctaHref: string;
  comingSoonBadge: string;
}) {
  return (
    <div
      className={`relative rounded-2xl p-6 md:p-8 flex flex-col ${
        highlighted
          ? "bg-gray-900 border-2 border-red-500/50 shadow-lg shadow-red-500/10"
          : "bg-gray-900 border border-gray-800"
      }`}
    >
      {plan.badge && (
        <div className="absolute -top-3 left-1/2 -translate-x-1/2">
          <span className="px-3 py-1 bg-red-600 text-white text-xs font-semibold rounded-full">
            {plan.badge}
          </span>
        </div>
      )}

      <div className="mb-6">
        <h3 className="text-lg font-semibold text-white">{plan.name}</h3>
        <p className="text-gray-500 text-sm mt-1">{plan.description}</p>
      </div>

      <div className="mb-6">
        <span className="text-4xl font-bold text-white">{price}</span>
        <span className="text-gray-400 text-sm ml-1">{period}</span>
      </div>

      <Link
        href={ctaHref}
        className={`block w-full text-center px-6 py-3 rounded-lg font-medium transition-all mb-8 ${
          highlighted
            ? "bg-red-600 hover:bg-red-700 text-white hover:shadow-lg hover:shadow-red-600/20"
            : "bg-gray-800 hover:bg-gray-700 text-white"
        }`}
      >
        {plan.cta}
      </Link>

      <ul className="space-y-3 flex-1">
        {plan.features.map((feature) => {
          const isComingSoon = feature.includes("coming soon") || feature.includes("출시 예정");
          return (
            <li key={feature} className="flex items-start gap-2.5">
              {CHECK_ICON}
              <span className={`text-sm ${isComingSoon ? "text-gray-500" : "text-gray-300"}`}>
                {isComingSoon ? (
                  <>
                    {feature.replace(/ \(coming soon\)| \(출시 예정\)/, "")}
                    <span className="ml-1.5 text-[10px] px-1.5 py-0.5 rounded-full bg-orange-500/15 text-orange-400 font-medium">
                      {comingSoonBadge}
                    </span>
                  </>
                ) : (
                  feature
                )}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
