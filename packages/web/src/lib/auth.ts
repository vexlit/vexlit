import { cache } from "react";
import { createSupabaseServer } from "./supabase-server";

/**
 * Request-scoped cached getUser.
 * React cache() deduplicates within the same server request,
 * so layout + page share a single auth call instead of two.
 */
export const getUser = cache(async () => {
  const supabase = await createSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  return user;
});
