import {
  createConnection,
  TextDocuments,
  ProposedFeatures,
  InitializeParams,
  InitializeResult,
  TextDocumentSyncKind,
  Diagnostic,
  DiagnosticSeverity,
  CodeAction,
  CodeActionKind,
  CodeActionParams,
  TextEdit,
  Range,
  Hover,
  HoverParams,
  MarkupKind,
} from "vscode-languageserver/node.js";
import { TextDocument } from "vscode-languageserver-textdocument";
import { RuleEngine } from "@vexlit/core";
import type { Vulnerability, Language } from "@vexlit/core";

/* ── Connection & document manager ── */

const connection = createConnection(ProposedFeatures.all);
const documents = new TextDocuments(TextDocument);
const engine = new RuleEngine();

/** Map document URI → latest vulnerabilities for hover & code actions */
const docVulns = new Map<string, Vulnerability[]>();

/* ── Language mapping ── */

const LANG_MAP: Record<string, Language> = {
  javascript: "javascript",
  javascriptreact: "javascript",
  typescript: "typescript",
  typescriptreact: "typescript",
  python: "python",
};

/* ── Severity mapping ── */

function toSeverity(sev: string): DiagnosticSeverity {
  switch (sev) {
    case "critical": return DiagnosticSeverity.Error;
    case "warning": return DiagnosticSeverity.Warning;
    default: return DiagnosticSeverity.Information;
  }
}

/* ── Initialization ── */

connection.onInitialize((_params: InitializeParams): InitializeResult => {
  return {
    capabilities: {
      textDocumentSync: TextDocumentSyncKind.Incremental,
      hoverProvider: true,
      codeActionProvider: {
        codeActionKinds: [CodeActionKind.QuickFix],
      },
    },
  };
});

/* ── Diagnostics (debounced) ── */

const DEBOUNCE_MS = 300;
const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();

function scheduleValidation(doc: TextDocument) {
  const uri = doc.uri;
  const existing = debounceTimers.get(uri);
  if (existing) clearTimeout(existing);

  debounceTimers.set(
    uri,
    setTimeout(() => {
      debounceTimers.delete(uri);
      validateDocument(doc);
    }, DEBOUNCE_MS)
  );
}

async function validateDocument(doc: TextDocument) {
  const lang = LANG_MAP[doc.languageId];
  if (!lang) {
    connection.sendDiagnostics({ uri: doc.uri, diagnostics: [] });
    docVulns.delete(doc.uri);
    return;
  }

  const text = doc.getText();
  const filePath = decodeURIComponent(
    doc.uri.replace("file:///", "").replace("file://", "")
  );

  try {
    const vulns = await engine.execute(filePath, text, lang);
    docVulns.set(doc.uri, vulns);

    const diagnostics: Diagnostic[] = vulns.map((v) => {
      const line = Math.max(0, v.line - 1); // LSP is 0-based
      return {
        range: {
          start: { line, character: Math.max(0, v.column - 1) },
          end: { line, character: Number.MAX_SAFE_INTEGER },
        },
        severity: toSeverity(v.severity),
        code: v.ruleId,
        source: "VEXLIT",
        message: v.message,
        data: { ruleId: v.ruleId, cwe: v.cwe, suggestion: v.suggestion },
      };
    });

    connection.sendDiagnostics({ uri: doc.uri, diagnostics });
  } catch {
    // Silently ignore parse errors during typing
    connection.sendDiagnostics({ uri: doc.uri, diagnostics: [] });
  }
}

/* ── Hover — show vulnerability details + CWE ── */

connection.onHover((params: HoverParams): Hover | null => {
  const vulns = docVulns.get(params.textDocument.uri);
  if (!vulns) return null;

  const line = params.position.line + 1; // back to 1-based
  const vuln = vulns.find((v) => v.line === line);
  if (!vuln) return null;

  const cweLink = vuln.cwe
    ? `[${vuln.cwe}](https://cwe.mitre.org/data/definitions/${vuln.cwe.replace("CWE-", "")}.html)`
    : "";

  const severity = vuln.severity === "critical" ? "**Critical**" : vuln.severity === "warning" ? "**Warning**" : "Info";

  const lines = [
    `### ${vuln.ruleName} (${vuln.ruleId})`,
    "",
    `**Severity:** ${severity}${cweLink ? ` | ${cweLink}` : ""}`,
    "",
    vuln.message,
  ];

  if (vuln.suggestion) {
    lines.push("", "---", "", `**Fix:** ${vuln.suggestion}`);
  }

  return {
    contents: {
      kind: MarkupKind.Markdown,
      value: lines.join("\n"),
    },
  };
});

/* ── Code Actions — Quick Fix with suggestion ── */

connection.onCodeAction((params: CodeActionParams): CodeAction[] => {
  const vulns = docVulns.get(params.textDocument.uri);
  if (!vulns) return [];

  const actions: CodeAction[] = [];

  for (const diag of params.context.diagnostics) {
    if (diag.source !== "VEXLIT") continue;

    const data = diag.data as { ruleId?: string; suggestion?: string } | undefined;
    if (!data?.suggestion) continue;

    // Find the matching vulnerability for a more precise fix
    const vuln = vulns.find(
      (v) => v.ruleId === data.ruleId && v.line === diag.range.start.line + 1
    );

    const action: CodeAction = {
      title: `VEXLIT: ${data.suggestion}`,
      kind: CodeActionKind.QuickFix,
      diagnostics: [diag],
      isPreferred: true,
    };

    // If the vuln has a snippet, provide a text edit that comments the vulnerable line
    // and adds a TODO with the fix suggestion
    if (vuln) {
      const line = diag.range.start.line;
      const doc = documents.get(params.textDocument.uri);
      if (doc) {
        const lineText = doc.getText({
          start: { line, character: 0 },
          end: { line, character: Number.MAX_SAFE_INTEGER },
        });
        const indent = lineText.match(/^\s*/)?.[0] ?? "";

        action.edit = {
          changes: {
            [params.textDocument.uri]: [
              TextEdit.insert(
                { line, character: 0 },
                `${indent}// TODO [VEXLIT ${vuln.ruleId}]: ${data.suggestion}\n`
              ),
            ],
          },
        };
      }
    }

    actions.push(action);
  }

  return actions;
});

/* ── Document lifecycle ── */

documents.onDidChangeContent((change) => {
  scheduleValidation(change.document);
});

documents.onDidClose((e) => {
  docVulns.delete(e.document.uri);
  debounceTimers.delete(e.document.uri);
  connection.sendDiagnostics({ uri: e.document.uri, diagnostics: [] });
});

/* ── Start ── */

documents.listen(connection);
connection.listen();
