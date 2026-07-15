import * as vscode from 'vscode';
import { IsolationSuggestion } from './types';

/**
 * VS Code does not let one extension force another into a separate OS
 * process on demand. The one *real*, documented lever available is the
 * `remote.extensionKind` setting, which controls whether a given extension
 * runs in the local "UI" extension host or in the remote/workspace
 * extension host when you're connected to a remote, container, or WSL
 * target (Remote-SSH / Dev Containers / WSL). Those are genuinely separate
 * OS processes — often on separate machines/containers entirely — so
 * moving an extension's execution across that boundary is real isolation,
 * not a simulation.
 *
 * If you are not currently connected to any remote/container/WSL target,
 * there is no second process to isolate into, and this module says so
 * plainly rather than pretending to sandbox anything.
 */

export interface RemoteContext {
  remoteName: string | null;
  isConnected: boolean;
  kindLabel: 'SSH' | 'Dev Container' | 'WSL' | 'Other remote' | 'None';
}

export function getRemoteContext(): RemoteContext {
  const remoteName = vscode.env.remoteName ?? null;
  if (!remoteName) {
    return { remoteName: null, isConnected: false, kindLabel: 'None' };
  }
  let kindLabel: RemoteContext['kindLabel'] = 'Other remote';
  if (remoteName.includes('ssh')) {
    kindLabel = 'SSH';
  } else if (remoteName.includes('wsl')) {
    kindLabel = 'WSL';
  } else if (remoteName.includes('dev-container') || remoteName.includes('attached-container')) {
    kindLabel = 'Dev Container';
  }
  return { remoteName, isConnected: true, kindLabel };
}

export function buildIsolationSuggestion(extensionId: string): IsolationSuggestion {
  const remote = getRemoteContext();

  if (!remote.isConnected) {
    return {
      extensionId,
      canSuggest: false,
      currentHost: 'local',
      suggestedExtensionKind: 'ui',
      rationale:
        'No remote, container, or WSL connection is active, so there is only one extension host process available right now — there is nowhere to isolate this extension into. ' +
        'Open this workspace via Remote-SSH, Dev Containers, or WSL to get a genuinely separate process boundary, then re-run this suggestion.'
    };
  }

  // When connected to a remote target, most extensions default to running
  // in the remote/workspace host (alongside the project's files). Forcing
  // an untrusted-looking extension to "ui" moves its execution back to your
  // local machine, away from remote workspace file access — or, depending
  // on what you're trying to protect, you may instead want to push a
  // locally-risky extension out to "workspace" so it runs in the
  // disposable container/remote instead of your local machine. We suggest
  // the container/remote direction by default since that's usually the
  // more disposable, more isolated environment.
  return {
    extensionId,
    canSuggest: true,
    currentHost: 'remote/container',
    suggestedExtensionKind: 'workspace',
    rationale:
      `Connected to a ${remote.kindLabel} target. You can override where "${extensionId}" runs via the ` +
      `"remote.extensionKind" setting. Running it as "workspace" confines its execution (and its fs/network access) ` +
      `to the ${remote.kindLabel} environment rather than your local machine; running it as "ui" does the reverse. ` +
      'Choose based on which side holds the secrets you care most about protecting.'
  };
}

export async function applyExtensionKindOverride(
  extensionId: string,
  kind: 'ui' | 'workspace'
): Promise<void> {
  const config = vscode.workspace.getConfiguration();
  const current = config.get<Record<string, string[]>>('remote.extensionKind', {});
  const updated = { ...current, [extensionId]: [kind] };
  const target = vscode.workspace.workspaceFolders
    ? vscode.ConfigurationTarget.Workspace
    : vscode.ConfigurationTarget.Global;
  await config.update('remote.extensionKind', updated, target);
}