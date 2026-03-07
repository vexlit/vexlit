import type { Metadata } from "next";
import { NextIntlClientProvider, hasLocale } from "next-intl";
import { notFound } from "next/navigation";
import { routing } from "@/i18n/routing";
import { ThemeProvider } from "@/components/theme-provider";
import { Toaster } from "sonner";

const BASE_URL = process.env.NEXT_PUBLIC_BASE_URL || "https://vexlit.com";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  const languages: Record<string, string> = {};
  for (const loc of routing.locales) {
    languages[loc] = `${BASE_URL}/${loc}`;
  }
  languages["x-default"] = `${BASE_URL}/en`;
  return {
    alternates: {
      canonical: `${BASE_URL}/${locale}`,
      languages,
    },
  };
}

export default async function LocaleLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;

  if (!hasLocale(routing.locales, locale)) {
    notFound();
  }

  const [common, landing, dashboard, settings, docs, pricing, vscode] = await Promise.all([
    import(`../../../messages/${locale}/common.json`),
    import(`../../../messages/${locale}/landing.json`),
    import(`../../../messages/${locale}/dashboard.json`),
    import(`../../../messages/${locale}/settings.json`),
    import(`../../../messages/${locale}/docs.json`),
    import(`../../../messages/${locale}/pricing.json`),
    import(`../../../messages/${locale}/vscode.json`),
  ]);
  const messages = {
    ...common.default,
    ...landing.default,
    ...dashboard.default,
    ...settings.default,
    ...docs.default,
    ...pricing.default,
    ...vscode.default,
  };

  return (
    <NextIntlClientProvider locale={locale} messages={messages}>
      <ThemeProvider>
        {children}
        <Toaster
          theme="dark"
          position="bottom-right"
          toastOptions={{
            className: "!bg-gray-900 !border-gray-800 !text-white",
          }}
        />
      </ThemeProvider>
    </NextIntlClientProvider>
  );
}
