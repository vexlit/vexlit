import createMiddleware from "next-intl/middleware";
import { routing } from "./i18n/routing";

export default createMiddleware(routing);

export const config = {
  matcher: [
    // Match all pathnames except:
    // - API routes (/api/...)
    // - Auth callback (/auth/...)
    // - Next.js internals (_next/...)
    // - Static files (files with extensions)
    "/((?!api|auth|_next|.*\\..*).*)",
  ],
};
