import * as vscode from 'vscode';
import { ExtensionRiskProfile } from './types';

export type TreeItemKind = 'status' | 'quickActionsRoot' | 'quickAction' | 'riskyRoot' | 'riskyExtension' | 'riskyEmpty';

export interface TreeState {
  ready: boolean;
  initErrorMessage?: string;
  monitoringOn: boolean;
  eventCount: number;
  highRiskCount: number;
  blockedCount: number;
}

export class ExtShieldTreeItem extends vscode.TreeItem {
  constructor(
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly kind: TreeItemKind,
    public readonly extensionId?: string
  ) {
    super(label, collapsibleState);
  }
}

/**
 * Backs the "ExtShield" Activity Bar view. Everything a user needs day to
 * day — toggling monitoring, opening the dashboard, scanning, and acting on
 * a specific flagged extension — lives here as a click or an inline icon,
 * so the Command Palette is no longer the primary way to use the extension.
 */
export class ExtShieldTreeProvider implements vscode.TreeDataProvider<ExtShieldTreeItem> {
  private emitter = new vscode.EventEmitter<ExtShieldTreeItem | undefined | void>();
  readonly onDidChangeTreeData = this.emitter.event;

  private riskProfiles: ExtensionRiskProfile[] = [];

  constructor(private getState: () => TreeState) {}

  refresh(): void {
    this.emitter.fire();
  }

  setRiskProfiles(profiles: ExtensionRiskProfile[]): void {
    this.riskProfiles = profiles;
    this.refresh();
  }

  getTreeItem(element: ExtShieldTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: ExtShieldTreeItem): ExtShieldTreeItem[] {
    if (!element) {
      return this.getRootItems();
    }
    if (element.kind === 'quickActionsRoot') {
      return this.getQuickActionItems();
    }
    if (element.kind === 'riskyRoot') {
      return this.getRiskyItems();
    }
    return [];
  }

  private getRootItems(): ExtShieldTreeItem[] {
    const state = this.getState();

    if (!state.ready) {
      const item = new ExtShieldTreeItem(
        'ExtShield failed to initialize — click for details',
        vscode.TreeItemCollapsibleState.None,
        'status'
      );
      item.iconPath = new vscode.ThemeIcon('warning');
      item.command = { command: 'extshield.showOutput', title: 'Show Output' };
      item.tooltip = state.initErrorMessage;
      return [item];
    }

    const statusItem = new ExtShieldTreeItem(
      state.monitoringOn ? 'Monitoring: ON' : 'Monitoring: OFF',
      vscode.TreeItemCollapsibleState.None,
      'status'
    );
    statusItem.iconPath = new vscode.ThemeIcon(state.monitoringOn ? 'shield' : 'circle-slash');
    statusItem.description = `${state.eventCount} events${state.highRiskCount ? ` · ${state.highRiskCount} high-risk` : ''}${
      state.blockedCount ? ` · ${state.blockedCount} blocked` : ''
    }`;
    statusItem.command = { command: 'extshield.toggleMonitoring', title: 'Toggle Monitoring' };
    statusItem.tooltip = 'Click to turn monitoring on/off';

    const quickActions = new ExtShieldTreeItem('Quick Actions', vscode.TreeItemCollapsibleState.Expanded, 'quickActionsRoot');
    quickActions.iconPath = new vscode.ThemeIcon('list-unordered');

    const riskyRoot = new ExtShieldTreeItem(
      `Extension Risk Scan${this.riskProfiles.length ? ` (${this.riskProfiles.length})` : ''}`,
      vscode.TreeItemCollapsibleState.Expanded,
      'riskyRoot'
    );
    riskyRoot.iconPath = new vscode.ThemeIcon('search');

    return [statusItem, quickActions, riskyRoot];
  }

  private getQuickActionItems(): ExtShieldTreeItem[] {
    const actions: Array<{ label: string; command: string; icon: string }> = [
      { label: 'Open Activity Dashboard', command: 'extshield.openDashboard', icon: 'graph' },
      { label: 'Scan Installed Extensions', command: 'extshield.scanExtensions', icon: 'search' },
      { label: 'Manage Trusted Extensions', command: 'extshield.manageTrustedExtensions', icon: 'verified' },
      { label: 'Suggest Extension Host Isolation…', command: 'extshield.suggestIsolation', icon: 'server-process' },
      { label: 'Set Access Policy…', command: 'extshield.setPolicy', icon: 'law' },
      { label: 'Export Activity Log as JSON', command: 'extshield.exportLog', icon: 'export' },
      { label: 'Show Historical Log Location', command: 'extshield.showLogLocation', icon: 'folder-opened' },
      { label: 'Clear In-Memory Log', command: 'extshield.clearLog', icon: 'trash' }
    ];
    return actions.map((a) => {
      const item = new ExtShieldTreeItem(a.label, vscode.TreeItemCollapsibleState.None, 'quickAction');
      item.iconPath = new vscode.ThemeIcon(a.icon);
      item.command = { command: a.command, title: a.label };
      return item;
    });
  }

  private getRiskyItems(): ExtShieldTreeItem[] {
    if (this.riskProfiles.length === 0) {
      const item = new ExtShieldTreeItem('Click to run a scan…', vscode.TreeItemCollapsibleState.None, 'riskyEmpty');
      item.iconPath = new vscode.ThemeIcon('info');
      item.command = { command: 'extshield.scanExtensions', title: 'Scan Installed Extensions' };
      return [item];
    }

    return this.riskProfiles.slice(0, 30).map((p) => {
      const item = new ExtShieldTreeItem(p.displayName, vscode.TreeItemCollapsibleState.None, 'riskyExtension', p.extensionId);
      item.description = `score ${p.riskScore}${p.trusted ? ' · trusted' : ''}`;
      item.tooltip = new vscode.MarkdownString(
        `**${p.extensionId}**\n\n${p.riskFactors.length ? p.riskFactors.map((f) => `- ${f}`).join('\n') : 'No notable risk factors.'}`
      );
      item.contextValue = 'riskyExtension';
      item.iconPath = new vscode.ThemeIcon(p.riskScore >= 60 ? 'error' : p.riskScore >= 30 ? 'warning' : 'pass');
      // Clicking the row itself does the single most common action (set a
      // policy); trust/isolation are available as inline icons via the
      // view/item/context menu (see package.json), so nothing here needs
      // the Command Palette.
      item.command = {
        command: 'extshield.treeSetPolicy',
        title: 'Set Access Policy',
        arguments: [item]
      };
      return item;
    });
  }
}