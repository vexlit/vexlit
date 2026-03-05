import Anthropic from "@anthropic-ai/sdk";
import { Vulnerability, Severity } from "./types.js";

interface LlmAnalysisResult {
  isRealVulnerability: boolean;
  adjustedSeverity: Severity;
  explanation: string;
}

export async function analyzeLlm(
  vulnerability: Vulnerability,
  fileContent: string,
  apiKey: string
): Promise<LlmAnalysisResult> {
  const client = new Anthropic({ apiKey });

  const contextStart = Math.max(0, vulnerability.line - 6);
  const contextEnd = vulnerability.line + 5;
  const lines = fileContent.split("\n");
  const contextLines = lines.slice(contextStart, contextEnd);
  const context = contextLines
    .map((line, i) => `${contextStart + i + 1}: ${line}`)
    .join("\n");

  const message = await client.messages.create({
    model: "claude-haiku-4-5-20251001",
    max_tokens: 512,
    messages: [
      {
        role: "user",
        content: `You are a security code reviewer. Analyze this potential vulnerability and respond ONLY with valid JSON, no other text.

Rule: ${vulnerability.ruleId} (${vulnerability.ruleName})
Detected: ${vulnerability.message}
File: ${vulnerability.filePath}
Line: ${vulnerability.line}

Code context:
\`\`\`
${context}
\`\`\`

Respond with this exact JSON format:
{"isRealVulnerability": true/false, "adjustedSeverity": "critical"/"warning"/"info", "explanation": "brief explanation"}`,
      },
    ],
  });

  const text =
    message.content[0].type === "text" ? message.content[0].text : "";

  try {
    const result = JSON.parse(text) as LlmAnalysisResult;
    return {
      isRealVulnerability: result.isRealVulnerability ?? true,
      adjustedSeverity: result.adjustedSeverity ?? vulnerability.severity,
      explanation: result.explanation ?? "",
    };
  } catch {
    return {
      isRealVulnerability: true,
      adjustedSeverity: vulnerability.severity,
      explanation: "LLM analysis could not be parsed",
    };
  }
}

export async function filterWithLlm(
  vulnerabilities: Vulnerability[],
  fileContents: Map<string, string>,
  apiKey: string
): Promise<Vulnerability[]> {
  const confirmed: Vulnerability[] = [];

  for (const vuln of vulnerabilities) {
    const content = fileContents.get(vuln.filePath);
    if (!content) {
      confirmed.push(vuln);
      continue;
    }

    const result = await analyzeLlm(vuln, content, apiKey);
    if (result.isRealVulnerability) {
      vuln.severity = result.adjustedSeverity;
      confirmed.push(vuln);
    }
  }

  return confirmed;
}
