import { getRequestConfig } from "next-intl/server";
import { routing } from "./routing";

async function loadMessages(locale: string) {
  const [common, landing, dashboard, settings, docs, pricing, vscode] = await Promise.all([
    import(`../../messages/${locale}/common.json`),
    import(`../../messages/${locale}/landing.json`),
    import(`../../messages/${locale}/dashboard.json`),
    import(`../../messages/${locale}/settings.json`),
    import(`../../messages/${locale}/docs.json`),
    import(`../../messages/${locale}/pricing.json`),
    import(`../../messages/${locale}/vscode.json`),
  ]);
  return {
    ...common.default,
    ...landing.default,
    ...dashboard.default,
    ...settings.default,
    ...docs.default,
    ...pricing.default,
    ...vscode.default,
  };
}

export default getRequestConfig(async ({ requestLocale }) => {
  let locale = await requestLocale;

  if (!locale || !routing.locales.includes(locale as "en" | "ko")) {
    locale = routing.defaultLocale;
  }

  return {
    locale,
    messages: await loadMessages(locale),
  };
});
