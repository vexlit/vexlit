import { NextResponse } from "next/server";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import { createSupabaseServer } from "@/lib/supabase-server";

const redis =
  process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN
    ? new Redis({
        url: process.env.UPSTASH_REDIS_REST_URL,
        token: process.env.UPSTASH_REDIS_REST_TOKEN,
      })
    : null;

// Anonymous: 5 scans / 60s, Authenticated: 20 scans / 60s
const anonLimiter = redis
  ? new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(5, "60 s"), prefix: "vexlit:demo:anon" })
  : null;
const authLimiter = redis
  ? new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(20, "60 s"), prefix: "vexlit:demo:auth" })
  : null;

// Max code size for demo: 50KB
const MAX_CODE_LENGTH = 50_000;

const EXT_MAP: Record<string, "javascript" | "typescript" | "python"> = {
  javascript: "javascript",
  typescript: "typescript",
  python: "python",
};

export async function POST(request: Request) {
  // Production guard: require Upstash env vars in production
  if (process.env.NODE_ENV === "production" && !redis) {
    return NextResponse.json(
      { error: "Rate limiting is not configured" },
      { status: 503 }
    );
  }

  const ip =
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";

  // Check authentication
  let userId: string | null = null;
  try {
    const supabase = await createSupabaseServer();
    const { data: { user } } = await supabase.auth.getUser();
    userId = user?.id ?? null;
  } catch {
    // Not authenticated — use anonymous limit
  }

  const limiter = userId ? authLimiter : anonLimiter;
  const key = userId ? `user:${userId}` : `ip:${ip}`;

  if (limiter) {
    const { success } = await limiter.limit(key);
    if (!success) {
      return NextResponse.json(
        { error: "Too many requests. Please wait a moment." },
        { status: 429 }
      );
    }
  }

  const body = await request.json();
  const { code, language } = body as { code?: string; language?: string };

  if (!code || typeof code !== "string") {
    return NextResponse.json({ error: "code is required" }, { status: 400 });
  }

  if (code.length > MAX_CODE_LENGTH) {
    return NextResponse.json(
      { error: "Code too large (max 50KB)" },
      { status: 400 }
    );
  }

  const lang = EXT_MAP[language ?? "javascript"] ?? "javascript";

  try {
    const { RuleEngine } = await import("@vexlit/core");
    const engine = new RuleEngine();
    const extForLang = { javascript: "js", typescript: "ts", python: "py" } as const;
    const demoFile = `demo.${extForLang[lang]}`;
    const vulns = await engine.execute(demoFile, code, lang);

    return NextResponse.json({
      vulnerabilities: vulns.map((v) => ({
        line: v.line,
        severity: v.severity,
        confidence: v.confidence,
        rule: v.ruleName,
        message: v.message,
        cwe: v.cwe,
        suggestion: v.suggestion,
      })),
    });
  } catch (err) {
    console.error("[scan/demo] Engine error:", err);
    return NextResponse.json(
      { error: "Scan engine error", detail: err instanceof Error ? err.message : String(err) },
      { status: 500 }
    );
  }
}
