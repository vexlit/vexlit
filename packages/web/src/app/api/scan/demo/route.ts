import { NextResponse } from "next/server";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

// Upstash Redis rate limiter: 5 demo scans per 60s sliding window per IP
const ratelimit =
  process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN
    ? new Ratelimit({
        redis: new Redis({
          url: process.env.UPSTASH_REDIS_REST_URL,
          token: process.env.UPSTASH_REDIS_REST_TOKEN,
        }),
        limiter: Ratelimit.slidingWindow(5, "60 s"),
        prefix: "vexlit:demo",
      })
    : null;

// Max code size for demo: 50KB
const MAX_CODE_LENGTH = 50_000;

const EXT_MAP: Record<string, "javascript" | "typescript" | "python"> = {
  javascript: "javascript",
  typescript: "typescript",
  python: "python",
};

export async function POST(request: Request) {
  const ip =
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";

  if (ratelimit) {
    const { success } = await ratelimit.limit(ip);
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
