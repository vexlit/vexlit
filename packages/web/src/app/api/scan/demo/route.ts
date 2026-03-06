import { NextResponse } from "next/server";

// Rate limit: 5 demo scans per minute per IP
const rateMap = new Map<string, { count: number; resetAt: number }>();

function checkRate(ip: string): boolean {
  const now = Date.now();
  const entry = rateMap.get(ip);
  if (!entry || now > entry.resetAt) {
    rateMap.set(ip, { count: 1, resetAt: now + 60_000 });
    return true;
  }
  if (entry.count >= 5) return false;
  entry.count++;
  return true;
}

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
  if (!checkRate(ip)) {
    return NextResponse.json(
      { error: "Too many requests. Please wait a moment." },
      { status: 429 }
    );
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
    const vulns = await engine.execute("demo.js", code, lang);

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
