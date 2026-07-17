import * as vscode from 'vscode';
import { setSelfExtensionPath } from './attribution';
import { Monitor, MonitorConfig } from './monitor';
import { PolicyManager } from './policyManager';
import { DashboardPanel } from './dashboardPanel';
import { scanInstalledExtensions } from './scanner';
import { LogStore } from './logStore';
import { TrustedExtensionsManager } from './trustedExtensions';
import { ThreatIntelService } from './threatIntel';
import { buildIsolationSuggestion, applyExtensionKindOverride } from './isolationAdvisor';
import { ExtShieldTreeProvider, ExtShieldTreeItem, TreeState } from './treeView';
import { ActivityEvent, ExtensionPolicy } from './types';

let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;
let monitor: Monitor | undefined;
let policyManager: PolicyManager | undefined;
let trustManager: TrustedExtensionsManager | undefined;
let threatIntel: ThreatIntelService | undefined;
let logStore: LogStore | undefined;
let eventLog: ActivityEvent[] = [];
let initError: string | undefined;
let treeProvider: ExtShieldTreeProvider | undefined;

function readConfig(): MonitorConfig & {
  enabled: boolean;
  logRetention: number;
  logRetentionDays: number;
  threatIntelEnabled: boolean;
  threatIntelCacheMinutes: number;
} {
  const cfg = vscode.workspace.getConfiguration('extshield');
  return {
    enabled: cfg.get<boolean>('enabled', true),
    blockOnPolicyViolation: cfg.get<boolean>('blockOnPolicyViolation', false),
    monitorEnvAccess: cfg.get<boolean>('monitorEnvAccess', false),
    notifyOnSecretAccess: cfg.get<boolean>('notifyOnSecretAccess', true),
    logRetention: cfg.get<number>('logRetentionEntries', 2000),
    logRetentionDays: cfg.get<number>('diskLogRetentionDays', 30),
    threatIntelEnabled: cfg.get<boolean>('threatIntel.enabled', true),
    threatIntelCacheMinutes: cfg.get<number>('threatIntel.cacheTtlMinutes', 60)
  };
}

function updateStatusBar(): void {
  if (!statusBarItem) {
    return;
  }
  if (initError) {
    statusBarItem.text = `$(warning) ExtShield: init failed`;
    statusBarItem.tooltip = initError;
  } else {
    const highRiskCount = eventLog.filter((e) => e.risk === 'high').length;
    statusBarItem.text = monitor?.isRunning()
      ? `$(shield) ExtShield: ${eventLog.length} events${highRiskCount ? ` ($(alert) ${highRiskCount})` : ''}`
      : `$(circle-slash) ExtShield: off`;
    statusBarItem.tooltip = 'Click to open ExtShield dashboard';
  }
  treeProvider?.refresh();
}

/**
 * True (and shows an explanatory message) if initialization failed. Every
 * command handler checks this before doing real work, so a failure during
 * startup produces a clear "not ready" message instead of leaving commands
 * unregistered entirely — which is what causes VS Code's generic "command
 * not found" error.
 */
function notReady(): boolean {
  if (initError) {
    vscode.window.showErrorMessage(
      `ExtShield did not finish initializing: ${initError}. See the "ExtShield" output channel for details.`
    );
    return true;
  }
  return false;
}

function dashboardCallbacks() {
  return {
    onSetPolicy: (extensionId: string) => promptSetPolicy(extensionId),
    onTrustExtension: async (extensionId: string) => {
      if (!trustManager) return;
      await trustManager.addTrusted(extensionId);
      vscode.window.showInformationMessage(`ExtShield: ${extensionId} marked as trusted.`);
      const profiles = scanInstalledExtensions(trustManager);
      DashboardPanel.current?.updateRiskProfiles(profiles);
      treeProvider?.setRiskProfiles(profiles);
    },
    onUntrustExtension: async (extensionId: string) => {
      if (!trustManager) return;
      await trustManager.removeTrusted(extensionId);
      vscode.window.showInformationMessage(`ExtShield: trust removed for ${extensionId}.`);
      const profiles = scanInstalledExtensions(trustManager);
      DashboardPanel.current?.updateRiskProfiles(profiles);
      treeProvider?.setRiskProfiles(profiles);
    },
    onSuggestIsolation: (extensionId: string) => promptIsolation(extensionId)
  };
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  // Output channel and status bar are extremely unlikely to fail and are
  // needed for everything else (including error reporting), so they're
  // created outside the try/catch.
  outputChannel = vscode.window.createOutputChannel('ExtShield');
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = 'extshield.openDashboard';
  context.subscriptions.push(statusBarItem, outputChannel);

  // Commands are registered FIRST and unconditionally. Each handler checks
  // notReady()/specific state before doing real work. This is the key
  // fix: previously, all commands were registered only after monitor/log
  // store/etc. initialization succeeded, so any failure during that
  // initialization left every single command unregistered — which is
  // exactly what produces VS Code's "command 'extshield.X' not found"
  // error. Now a failure anywhere in initialization can only ever disable
  // functionality, never the command's existence.
  // The sidebar view is registered up front for the same reason commands
  // are: it should never disappear just because later initialization fails.
  treeProvider = new ExtShieldTreeProvider(
    (): TreeState => ({
      ready: !initError,
      initErrorMessage: initError,
      monitoringOn: monitor?.isRunning() ?? false,
      eventCount: eventLog.length,
      highRiskCount: eventLog.filter((e) => e.risk === 'high').length,
      blockedCount: eventLog.filter((e) => e.blocked).length
    })
  );
  context.subscriptions.push(vscode.window.registerTreeDataProvider('extshield.mainView', treeProvider));

  registerCommands(context);

  try {
    await initialize(context);
    outputChannel.appendLine('ExtShield initialized successfully.');
  } catch (err: any) {
    initError = err?.message ?? String(err);
    outputChannel.appendLine(`[error] ExtShield failed to fully initialize: ${initError}`);
    outputChannel.show(true);
    vscode.window.showErrorMessage(
      `ExtShield failed to fully initialize: ${initError}. Commands are registered but may not work until this is resolved — see the "ExtShield" output channel.`
    );
  }
  updateStatusBar();
}

async function initialize(context: vscode.ExtensionContext): Promise<void> {
  setSelfExtensionPath(context.extensionPath);
  policyManager = new PolicyManager(context);
  trustManager = new TrustedExtensionsManager(context);

  const config = readConfig();

  logStore = new LogStore(context);
  await logStore.init();
  eventLog = await logStore.loadRecent(config.logRetention);
  logStore.pruneOldFiles(config.logRetentionDays).catch(() => undefined);
  outputChannel.appendLine(`Loaded ${eventLog.length} historical events from ${logStore.storageLocation}`);

  threatIntel = new ThreatIntelService({
    enabled: config.threatIntelEnabled,
    cacheTtlMinutes: config.threatIntelCacheMinutes,
    timeoutMs: 5000
  });

  const onEvent = (evt: ActivityEvent) => {
    eventLog.push(evt);
    logStore?.queue(evt);
    const cfg = readConfig();
    if (eventLog.length > cfg.logRetention) {
      eventLog = eventLog.slice(eventLog.length - cfg.logRetention);
    }
    if (evt.risk === 'high') {
      outputChannel.appendLine(
        `[${new Date(evt.timestamp).toISOString()}] HIGH RISK ${evt.blocked ? '(BLOCKED) ' : ''}` +
          `${evt.extensionId ?? '(unattributed)'} :: ${evt.kind} :: ${evt.target}${evt.reason ? ' — ' + evt.reason : ''}`
      );
    }
    DashboardPanel.current?.updateEvents(eventLog);
    updateStatusBar();

    if (evt.kind === 'net.request' && !evt.blocked && threatIntel) {
      threatIntel.checkHost(evt.target).then((result) => {
        evt.threatIntel = result;
        if (result.malicious) {
          evt.risk = 'high';
          outputChannel.appendLine(
            `[threat-intel] ${evt.extensionId ?? '(unattributed)'} contacted ${evt.target} — flagged by ${result.source}${
              result.detail ? ': ' + result.detail : ''
            }`
          );
          vscode.window
            .showWarningMessage(
              `ExtShield: ${evt.extensionId ?? 'An unattributed extension'} contacted ${evt.target}, which is flagged by ${result.source}.`,
              'Open Dashboard'
            )
            .then((choice) => {
              if (choice === 'Open Dashboard') {
                vscode.commands.executeCommand('extshield.openDashboard');
              }
            });
        }
        DashboardPanel.current?.updateEvents(eventLog);
        updateStatusBar();
      });
    }
  };

  const onSecretHit = (evt: ActivityEvent, matches: string[]) => {
    const label = evt.extensionId ?? 'an unattributed extension';
    vscode.window
      .showWarningMessage(
        `ExtShield: ${label} accessed a file that looks sensitive (${evt.target}) — matched: ${matches.join(', ')}`,
        'Open Dashboard',
        'Set Policy'
      )
      .then((choice) => {
        if (choice === 'Open Dashboard') {
          vscode.commands.executeCommand('extshield.openDashboard');
        } else if (choice === 'Set Policy' && evt.extensionId) {
          promptSetPolicy(evt.extensionId);
        }
      });
  };

  const onWarning = (message: string) => {
    outputChannel.appendLine(`[warning] ${message}`);
  };

  monitor = new Monitor(policyManager, config, onEvent, onSecretHit, onWarning);

  if (config.enabled) {
    try {
      monitor.start();
      outputChannel.appendLine('ExtShield monitoring started.');
    } catch (err: any) {
      outputChannel.appendLine(`[warning] Monitor failed to start: ${err?.message ?? err}. ExtShield loaded but monitoring is inactive.`);
    }
  }

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('extshield') && monitor && policyManager) {
        const newCfg = readConfig();
        monitor.stop();
        monitor = new Monitor(policyManager, newCfg, onEvent, onSecretHit, onWarning);
        threatIntel?.updateConfig({
          enabled: newCfg.threatIntelEnabled,
          cacheTtlMinutes: newCfg.threatIntelCacheMinutes,
          timeoutMs: 5000
        });
        if (newCfg.enabled) {
          try {
            monitor.start();
          } catch (err: any) {
            onWarning(`Monitor failed to restart after settings change: ${err?.message ?? err}`);
          }
        }
        updateStatusBar();
      }
    })
  );

  context.subscriptions.push({
    dispose: () => {
      monitor?.stop();
      logStore?.flush();
    }
  });
}

function registerCommands(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('extshield.openDashboard', () => {
      if (notReady()) return;
      const panel = DashboardPanel.createOrShow(context.extensionUri, dashboardCallbacks());
      panel.updateEvents(eventLog);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('extshield.scanExtensions', () => {
      if (notReady() || !trustManager) return;
      const profiles = scanInstalledExtensions(trustManager);
      const highRisk = profiles.filter((p) => p.riskScore >= 40).length;
      vscode.window.showInformationMessage(
        `ExtShield scanned ${profiles.length} extensions — ${highRisk} flagged as higher-risk. See the sidebar or dashboard for details.`
      );
      treeProvider?.setRiskProfiles(profiles);
      DashboardPanel.current?.updateRiskProfiles(profiles);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('extshield.setPolicy', async () => {
      if (notReady()) return;
      const installed = vscode.extensions.all.filter((e) => !e.packageJSON?.isBuiltin);
      const pick = await vscode.window.showQuickPick(
        installed.map((e) => ({ label: e.packageJSON?.displayName || e.id, description: e.id })),
        { placeHolder: 'Choose an extension to set a policy for' }
      );
      if (pick) {
        await promptSetPolicy(pick.description!);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('extshield.manageTrustedExtensions', async () => {
      if (notReady() || !trustManager) return;
      const tm = trustManager;
      const installed = vscode.extensions.all.filter((e) => !e.packageJSON?.isBuiltin);
      const items = installed.map((e) => ({
        label: (tm.isTrusted(e.id) ? '$(check) ' : '') + (e.packageJSON?.displayName || e.id),
        description: e.id,
        picked: tm.isTrusted(e.id)
      }));
      const picks = await vscode.window.showQuickPick(items, {
        canPickMany: true,
        placeHolder: 'Check the extensions you want ExtShield to treat as trusted'
      });
      if (!picks) {
        return;
      }
      const pickedIds = new Set(picks.map((p) => p.description));
      for (const item of items) {
        const id = item.description!;
        if (pickedIds.has(id) && !tm.isTrusted(id)) {
          await tm.addTrusted(id);
        } else if (!pickedIds.has(id) && tm.isTrusted(id)) {
          await tm.removeTrusted(id);
        }
      }
      vscode.window.showInformationMessage(`ExtShield: trusted-extensions list updated (${pickedIds.size} trusted).`);
      treeProvider?.setRiskProfiles(scanInstalledExtensions(tm));
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('extshield.suggestIsolation', async () => {
      if (notReady()) return;
      const installed = vscode.extensions.all.filter((e) => !e.packageJSON?.isBuiltin);
      const pick = await vscode.window.showQuickPick(
        installed.map((e) => ({ label: e.packageJSON?.displayName || e.id, description: e.id })),
        { placeHolder: 'Choose an extension to get an isolation suggestion for' }
      );
      if (pick) {
        await promptIsolation(pick.description!);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('extshield.toggleMonitoring', async () => {
      if (notReady()) return;
      const cfg = vscode.workspace.getConfiguration('extshield');
      const current = cfg.get<boolean>('enabled', true);
      await cfg.update('enabled', !current, vscode.ConfigurationTarget.Global);
      vscode.window.showInformationMessage(`ExtShield monitoring ${!current ? 'enabled' : 'disabled'}.`);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('extshield.clearLog', () => {
      if (notReady()) return;
      eventLog = [];
      DashboardPanel.current?.updateEvents(eventLog);
      updateStatusBar();
      vscode.window.showInformationMessage('ExtShield in-memory activity log cleared. Historical data on disk is untouched.');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('extshield.exportLog', async () => {
      if (notReady()) return;
      const all = (await logStore?.loadAll()) ?? [];
      const json = JSON.stringify(all.length ? all : eventLog, null, 2);
      const doc = await vscode.workspace.openTextDocument({ content: json, language: 'json' });
      await vscode.window.showTextDocument(doc);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('extshield.showLogLocation', () => {
      if (notReady() || !logStore) return;
      const location = logStore.storageLocation;
      vscode.window.showInformationMessage(`ExtShield stores its historical activity log at: ${location}`, 'Copy Path').then((choice) => {
        if (choice === 'Copy Path') {
          vscode.env.clipboard.writeText(location);
        }
      });
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('extshield.showOutput', () => {
      outputChannel.show(true);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('extshield.refreshTree', () => {
      if (notReady() || !trustManager) {
        treeProvider?.refresh();
        return;
      }
      treeProvider?.setRiskProfiles(scanInstalledExtensions(trustManager));
    })
  );

  // These three are invoked from the sidebar's inline row icons
  // (view/item/context in package.json), which pass the clicked
  // ExtShieldTreeItem as the argument — that's how a specific extension ID
  // reaches the handler without re-prompting the user to pick one.
  context.subscriptions.push(
    vscode.commands.registerCommand('extshield.treeSetPolicy', async (item?: ExtShieldTreeItem) => {
      if (notReady()) return;
      if (item?.extensionId) {
        await promptSetPolicy(item.extensionId);
      } else {
        await vscode.commands.executeCommand('extshield.setPolicy');
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('extshield.treeToggleTrust', async (item?: ExtShieldTreeItem) => {
      if (notReady() || !trustManager || !item?.extensionId) return;
      const tm = trustManager;
      if (tm.isTrusted(item.extensionId)) {
        await tm.removeTrusted(item.extensionId);
        vscode.window.showInformationMessage(`ExtShield: trust removed for ${item.extensionId}.`);
      } else {
        await tm.addTrusted(item.extensionId);
        vscode.window.showInformationMessage(`ExtShield: ${item.extensionId} marked as trusted.`);
      }
      const profiles = scanInstalledExtensions(tm);
      treeProvider?.setRiskProfiles(profiles);
      DashboardPanel.current?.updateRiskProfiles(profiles);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('extshield.treeSuggestIsolation', async (item?: ExtShieldTreeItem) => {
      if (notReady()) return;
      if (item?.extensionId) {
        await promptIsolation(item.extensionId);
      } else {
        await vscode.commands.executeCommand('extshield.suggestIsolation');
      }
    })
  );
}

async function promptSetPolicy(extensionId: string): Promise<void> {
  if (!policyManager) {
    vscode.window.showErrorMessage('ExtShield is not fully initialized yet.');
    return;
  }
  const existing = policyManager.getPolicy(extensionId);

  const pathsInput = await vscode.window.showInputBox({
    prompt: `Allowed path prefixes for ${extensionId} (comma-separated, leave blank for no restriction)`,
    value: existing?.allowedPathPrefixes.join(', ') ?? '',
    placeHolder: '/home/me/project/src, /home/me/project/config'
  });
  if (pathsInput === undefined) {
    return; // cancelled
  }

  const blockNetwork = await vscode.window.showQuickPick(['Allow network access', 'Block network access'], {
    placeHolder: `Network policy for ${extensionId}`
  });
  if (blockNetwork === undefined) {
    return;
  }

  const blockChild = await vscode.window.showQuickPick(['Allow spawning processes', 'Block spawning processes'], {
    placeHolder: `Process policy for ${extensionId}`
  });
  if (blockChild === undefined) {
    return;
  }

  const policy: ExtensionPolicy = {
    extensionId,
    allowedPathPrefixes: pathsInput
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    blockNetwork: blockNetwork === 'Block network access',
    blockChildProcess: blockChild === 'Block spawning processes'
  };

  await policyManager.setPolicy(policy);
  vscode.window.showInformationMessage(
    `ExtShield policy saved for ${extensionId}. Enable "extshield.blockOnPolicyViolation" in settings to enforce it.`
  );
}

async function promptIsolation(extensionId: string): Promise<void> {
  const suggestion = buildIsolationSuggestion(extensionId);

  if (!suggestion.canSuggest) {
    vscode.window.showInformationMessage(`ExtShield: ${suggestion.rationale}`);
    return;
  }

  const choice = await vscode.window.showInformationMessage(
    suggestion.rationale,
    { modal: true },
    'Run in remote/container',
    'Run in local UI host'
  );
  if (!choice) {
    return;
  }

  const kind = choice === 'Run in remote/container' ? 'workspace' : 'ui';
  await applyExtensionKindOverride(extensionId, kind);
  vscode.window
    .showInformationMessage(
      `ExtShield: set "remote.extensionKind" override for ${extensionId} to ["${kind}"]. Reload the window for it to take effect.`,
      'Reload Window'
    )
    .then((c) => {
      if (c === 'Reload Window') {
        vscode.commands.executeCommand('workbench.action.reloadWindow');
      }
    });
}

export function deactivate(): void {
  monitor?.stop();
  logStore?.flush();
}
