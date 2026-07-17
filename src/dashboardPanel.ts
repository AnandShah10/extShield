import * as vscode from 'vscode';
import { ActivityEvent, ExtensionRiskProfile } from './types';

export interface DashboardCallbacks {
  onSetPolicy: (extensionId: string) => void;
  onTrustExtension: (extensionId: string) => void;
  onUntrustExtension: (extensionId: string) => void;
  onSuggestIsolation: (extensionId: string) => void;
}

export class DashboardPanel {
  public static current: DashboardPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];

  static createOrShow(extensionUri: vscode.Uri, callbacks: DashboardCallbacks): DashboardPanel {
    const column = vscode.window.activeTextEditor?.viewColumn;
    if (DashboardPanel.current) {
      DashboardPanel.current.panel.reveal(column);
      return DashboardPanel.current;
    }
    const panel = vscode.window.createWebviewPanel(
      'extshieldDashboard',
      'ExtShield Activity Dashboard',
      column ?? vscode.ViewColumn.One,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    DashboardPanel.current = new DashboardPanel(panel, callbacks);
    return DashboardPanel.current;
  }

  private constructor(panel: vscode.WebviewPanel, callbacks: DashboardCallbacks) {
    this.panel = panel;
    this.panel.webview.html = this.renderShell();
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
    this.panel.webview.onDidReceiveMessage(
      (msg) => {
        if (typeof msg?.extensionId !== 'string') {
          return;
        }
        switch (msg.type) {
          case 'setPolicy':
            callbacks.onSetPolicy(msg.extensionId);
            break;
          case 'trustExtension':
            callbacks.onTrustExtension(msg.extensionId);
            break;
          case 'untrustExtension':
            callbacks.onUntrustExtension(msg.extensionId);
            break;
          case 'suggestIsolation':
            callbacks.onSuggestIsolation(msg.extensionId);
            break;
        }
      },
      null,
      this.disposables
    );
  }

  updateEvents(events: ActivityEvent[]): void {
    this.panel.webview.postMessage({ type: 'events', events: events.slice(-500) });
  }

  updateRiskProfiles(profiles: ExtensionRiskProfile[]): void {
    this.panel.webview.postMessage({ type: 'profiles', profiles });
  }

  dispose(): void {
    DashboardPanel.current = undefined;
    this.panel.dispose();
    while (this.disposables.length) {
      this.disposables.pop()?.dispose();
    }
  }

  private renderShell(): string {
    return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); background: var(--vscode-editor-background); padding: 12px; }
  h2 { margin-top: 0; }
  .summary { display: flex; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }
  .card { border: 1px solid var(--vscode-widget-border, #444); border-radius: 6px; padding: 10px 14px; min-width: 140px; }
  .card .n { font-size: 22px; font-weight: 600; }
  table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
  th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--vscode-widget-border, #333); vertical-align: top; }
  th { position: sticky; top: 0; background: var(--vscode-editor-background); cursor: pointer; }
  tr.high { background: rgba(255, 80, 80, 0.12); }
  tr.medium { background: rgba(255, 200, 80, 0.10); }
  tr.blocked td:first-child::before { content: "🚫 "; }
  .risk-badge { padding: 1px 6px; border-radius: 10px; font-size: 11px; white-space: nowrap; }
  .risk-high { background: #7a1f1f; color: #fff; }
  .risk-medium { background: #7a5a1f; color: #fff; }
  .risk-low { background: #2f5132; color: #fff; }
  .badge { padding: 1px 6px; border-radius: 10px; font-size: 10.5px; white-space: nowrap; display: inline-block; margin-right: 4px; }
  .badge-trusted { background: #1f4a7a; color: #fff; }
  .badge-malicious { background: #7a1f1f; color: #fff; }
  .badge-clean { background: #2f5132; color: #fff; }
  .badge-unchecked { background: #555; color: #ddd; }
  .tabs { margin-bottom: 10px; }
  .tabs button { background: none; border: none; color: var(--vscode-foreground); padding: 6px 10px; cursor: pointer; border-bottom: 2px solid transparent; }
  .tabs button.active { border-bottom: 2px solid var(--vscode-focusBorder, #4a90e2); font-weight: 600; }
  .pane { display: none; }
  .pane.active { display: block; }
  input[type=text] { background: var(--vscode-input-background); color: var(--vscode-input-foreground); border: 1px solid var(--vscode-input-border, #555); padding: 4px 6px; margin-bottom: 8px; width: 260px; }
  .linkBtn { cursor: pointer; color: var(--vscode-textLink-foreground); background: none; border: none; text-decoration: underline; font-size: 12px; padding: 0; margin-right: 10px; }
  .factors { font-size: 11px; opacity: 0.85; }
  .empty { opacity: 0.6; font-style: italic; padding: 20px 0; }
  .actions button { display: block; margin-bottom: 4px; }
</style>
</head>
<body>
  <h2>🛡️ ExtShield</h2>
  <div class="summary" id="summary"></div>

  <div class="tabs">
    <button class="active" data-tab="activity">Activity Log</button>
    <button data-tab="risk">Extension Risk Scan</button>
  </div>

  <div class="pane active" id="pane-activity">
    <input type="text" id="filterInput" placeholder="Filter by extension id or target..." />
    <table id="eventsTable">
      <thead><tr><th>Time</th><th>Extension</th><th>Kind</th><th>Target</th><th>Risk</th><th>Threat Intel</th></tr></thead>
      <tbody></tbody>
    </table>
    <div class="empty" id="eventsEmpty">No activity recorded yet. Monitoring runs automatically once other extensions start doing file/network work.</div>
  </div>

  <div class="pane" id="pane-risk">
    <table id="riskTable">
      <thead><tr><th>Extension</th><th>Score</th><th>Factors</th><th>Actions</th></tr></thead>
      <tbody></tbody>
    </table>
    <div class="empty" id="riskEmpty">Run "ExtShield: Scan Installed Extensions for Risk" to populate this tab.</div>
  </div>

<script>
  const vscode = acquireVsCodeApi();
  let allEvents = [];
  let allProfiles = [];

  document.querySelectorAll('.tabs button').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tabs button').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('pane-' + btn.dataset.tab).classList.add('active');
    });
  });

  document.getElementById('filterInput').addEventListener('input', renderEvents);

  window.addEventListener('message', (event) => {
    const msg = event.data;
    if (msg.type === 'events') {
      allEvents = msg.events;
      renderEvents();
      renderSummary();
    } else if (msg.type === 'profiles') {
      allProfiles = msg.profiles;
      renderProfiles();
    }
  });

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function renderSummary() {
    const total = allEvents.length;
    const blocked = allEvents.filter(e => e.blocked).length;
    const high = allEvents.filter(e => e.risk === 'high').length;
    const flagged = allEvents.filter(e => e.threatIntel && e.threatIntel.malicious).length;
    const byExt = new Set(allEvents.map(e => e.extensionId).filter(Boolean));
    document.getElementById('summary').innerHTML = \`
      <div class="card"><div class="n">\${total}</div><div>Events logged</div></div>
      <div class="card"><div class="n">\${high}</div><div>High-risk events</div></div>
      <div class="card"><div class="n">\${blocked}</div><div>Blocked calls</div></div>
      <div class="card"><div class="n">\${flagged}</div><div>Flagged by threat intel</div></div>
      <div class="card"><div class="n">\${byExt.size}</div><div>Extensions observed</div></div>
    \`;
  }

  function intelBadge(e) {
    if (e.kind !== 'net.request') return '';
    const ti = e.threatIntel;
    if (!ti || !ti.checked) return '<span class="badge badge-unchecked">checking…</span>';
    if (ti.malicious) {
      const conf = typeof ti.confidence === 'number' ? ti.confidence : null;
      return '<span class="badge badge-malicious" title="' + escapeHtml(ti.detail || '') + '">flagged' + (conf !== null ? ' (' + conf + '% confidence)' : '') + ': ' + escapeHtml(ti.source) + '</span>';
    }
    return '<span class="badge badge-clean">clean (' + escapeHtml(ti.source) + ')</span>';
  }

  function renderEvents() {
    const filter = document.getElementById('filterInput').value.toLowerCase();
    const tbody = document.querySelector('#eventsTable tbody');
    const rows = [...allEvents].reverse().filter(e => {
      if (!filter) return true;
      return (e.extensionId || '').toLowerCase().includes(filter) || (e.target || '').toLowerCase().includes(filter);
    });
    document.getElementById('eventsEmpty').style.display = rows.length ? 'none' : 'block';
    tbody.innerHTML = rows.map(e => {
      const time = new Date(e.timestamp).toLocaleTimeString();
      const cls = (e.blocked ? 'blocked ' : '') + e.risk;
      return \`<tr class="\${cls}">
        <td>\${time}</td>
        <td>\${escapeHtml(e.extensionId || '(unattributed)')}</td>
        <td>\${escapeHtml(e.kind)}</td>
        <td title="\${escapeHtml(e.reason || '')}">\${escapeHtml(e.target)}</td>
        <td><span class="risk-badge risk-\${e.risk}">\${e.risk}</span></td>
        <td>\${intelBadge(e)}</td>
      </tr>\`;
    }).join('');
  }

  function renderProfiles() {
    document.getElementById('riskEmpty').style.display = allProfiles.length ? 'none' : 'block';
    const tbody = document.querySelector('#riskTable tbody');
    tbody.innerHTML = allProfiles.map(p => {
      const trustBadge = p.trusted
        ? '<span class="badge badge-trusted">trusted (' + escapeHtml(p.trustSource || '') + ')</span>'
        : '';
      const trustAction = p.trusted
        ? '<button class="linkBtn untrustBtn" data-id="' + escapeHtml(p.extensionId) + '">Remove trust</button>'
        : '<button class="linkBtn trustBtn" data-id="' + escapeHtml(p.extensionId) + '">Mark trusted</button>';
      return \`
      <tr>
        <td>\${escapeHtml(p.displayName)} \${trustBadge}<br/><span class="factors">\${escapeHtml(p.extensionId)}</span></td>
        <td>\${p.riskScore}</td>
        <td class="factors">\${p.riskFactors.map(escapeHtml).join('<br/>') || '—'}</td>
        <td class="actions">
          <button class="linkBtn setPolicyBtn" data-id="\${escapeHtml(p.extensionId)}">Set policy…</button>
          \${trustAction}
          <button class="linkBtn isolationBtn" data-id="\${escapeHtml(p.extensionId)}">Suggest isolation…</button>
        </td>
      </tr>\`;
    }).join('');
    tbody.querySelectorAll('.setPolicyBtn').forEach(btn => {
      btn.addEventListener('click', () => vscode.postMessage({ type: 'setPolicy', extensionId: btn.dataset.id }));
    });
    tbody.querySelectorAll('.trustBtn').forEach(btn => {
      btn.addEventListener('click', () => vscode.postMessage({ type: 'trustExtension', extensionId: btn.dataset.id }));
    });
    tbody.querySelectorAll('.untrustBtn').forEach(btn => {
      btn.addEventListener('click', () => vscode.postMessage({ type: 'untrustExtension', extensionId: btn.dataset.id }));
    });
    tbody.querySelectorAll('.isolationBtn').forEach(btn => {
      btn.addEventListener('click', () => vscode.postMessage({ type: 'suggestIsolation', extensionId: btn.dataset.id }));
    });
  }
</script>
</body>
</html>`;
  }
}
