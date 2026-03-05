import { createSupabaseServer } from "@/lib/supabase-server";
import { redirect } from "next/navigation";
import { LoginButton } from "./login-button";

export default async function LoginPage() {
  const supabase = await createSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (user) redirect("/dashboard");

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950">
      <div className="max-w-md w-full space-y-8 p-8">
        <div className="text-center">
          <h1 className="text-4xl font-bold text-white">VEXLIT</h1>
          <p className="mt-2 text-gray-400">
            AI-powered code security scanner
          </p>
        </div>

        <LoginButton />
      </div>
    </div>
  );
}
