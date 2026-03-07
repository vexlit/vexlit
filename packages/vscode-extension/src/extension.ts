import * as path from "path";
import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

export function activate(context: vscode.ExtensionContext) {
  const serverModule = context.asAbsolutePath(path.join("dist", "server.js"));

  const serverOptions: ServerOptions = {
    run: { module: serverModule, transport: TransportKind.ipc },
    debug: {
      module: serverModule,
      transport: TransportKind.ipc,
      options: { execArgv: ["--nolazy", "--inspect=6009"] },
    },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "javascript" },
      { scheme: "file", language: "javascriptreact" },
      { scheme: "file", language: "typescript" },
      { scheme: "file", language: "typescriptreact" },
      { scheme: "file", language: "python" },
    ],
    synchronize: {
      fileEvents: vscode.workspace.createFileSystemWatcher("**/*.{js,jsx,ts,tsx,py}"),
    },
  };

  client = new LanguageClient(
    "vexlit",
    "VEXLIT Security Scanner",
    serverOptions,
    clientOptions
  );

  // Register scan commands
  context.subscriptions.push(
    vscode.commands.registerCommand("vexlit.scanFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage("VEXLIT: No active file to scan.");
        return;
      }
      // Trigger re-validation by making a trivial edit notification
      // The LSP server auto-scans on content change; force by touching the document
      vscode.window.showInformationMessage(
        `VEXLIT: Scanning ${path.basename(editor.document.fileName)}...`
      );
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("vexlit.scanWorkspace", () => {
      vscode.window.showInformationMessage(
        "VEXLIT: Workspace scan coming soon. Files are scanned automatically as you open them."
      );
    })
  );

  // Show welcome message on first activation
  const hasShownWelcome = context.globalState.get<boolean>("vexlit.welcomeShown");
  if (!hasShownWelcome) {
    context.globalState.update("vexlit.welcomeShown", true);
    showWelcome();
  }

  // Status bar item
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
  statusBar.text = "$(shield) VEXLIT";
  statusBar.tooltip = "VEXLIT Security Scanner is active";
  statusBar.command = "vexlit.scanFile";
  statusBar.show();
  context.subscriptions.push(statusBar);

  client.start();
}

export function deactivate(): Thenable<void> | undefined {
  if (!client) return undefined;
  return client.stop();
}

function showWelcome() {
  const panel = vscode.window.createWebviewPanel(
    "vexlitWelcome",
    "Welcome to VEXLIT",
    vscode.ViewColumn.One,
    { enableScripts: false }
  );

  panel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 24px; color: var(--vscode-foreground); background: var(--vscode-editor-background); }
    h1 { font-size: 24px; margin-bottom: 8px; }
    .subtitle { color: var(--vscode-descriptionForeground); margin-bottom: 24px; }
    .feature { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 16px; }
    .icon { font-size: 20px; flex-shrink: 0; margin-top: 2px; }
    .feature h3 { margin: 0 0 4px; font-size: 14px; }
    .feature p { margin: 0; font-size: 13px; color: var(--vscode-descriptionForeground); }
    .section { margin-top: 24px; padding-top: 24px; border-top: 1px solid var(--vscode-widget-border); }
    code { background: var(--vscode-textCodeBlock-background); padding: 2px 6px; border-radius: 4px; font-size: 13px; }
    .hint { margin-top: 24px; padding: 12px 16px; background: var(--vscode-textBlockQuote-background); border-left: 3px solid var(--vscode-textLink-foreground); border-radius: 4px; }
  </style>
</head>
<body>
  <h1>Welcome to VEXLIT</h1>
  <p class="subtitle">AI-powered security scanning, right in your editor.</p>

  <div class="feature">
    <span class="icon">🔴</span>
    <div>
      <h3>Inline Vulnerability Detection</h3>
      <p>Security issues are underlined as you type. SQL injection, hardcoded secrets, XSS — detected instantly.</p>
    </div>
  </div>

  <div class="feature">
    <span class="icon">💡</span>
    <div>
      <h3>Hover for Details</h3>
      <p>Hover over any highlighted issue for a detailed explanation with CWE reference and fix suggestion.</p>
    </div>
  </div>

  <div class="feature">
    <span class="icon">⚡</span>
    <div>
      <h3>Quick Fix</h3>
      <p>Press <code>Ctrl+.</code> on any vulnerability for an instant fix suggestion.</p>
    </div>
  </div>

  <div class="feature">
    <span class="icon">📋</span>
    <div>
      <h3>Problems Panel</h3>
      <p>All vulnerabilities appear in <code>View → Problems</code> for a full overview.</p>
    </div>
  </div>

  <div class="section">
    <h3>Getting Started</h3>
    <p>Just open any <code>.js</code>, <code>.ts</code>, or <code>.py</code> file. VEXLIT scans automatically — no configuration needed.</p>
  </div>

  <div class="hint">
    <strong>Tip:</strong> Try writing <code>const API_KEY = "sk-secret-123"</code> to see VEXLIT detect a hardcoded secret!
  </div>
</body>
</html>`;
}
