import * as vscode from 'vscode';
import { ExtensionRiskProfile } from './types';
import { TrustedExtensionsManager } from './trustedExtensions';

const BROAD_ACTIVATION_EVENTS = new Set(['*', 'onStartupFinished']);
const TRUSTED_SCORE_DISCOUNT = 25;

/**
 * Produces a heuristic 0-100 risk score per installed extension based only
 * on its published manifest (no dynamic analysis). This is a rough signal
 * for prioritizing what to watch, not a verdict — a high score does not
 * mean an extension is malicious, and a low score does not guarantee safety.
 *
 * Extensions on the trusted allowlist get a flat score discount (not a
 * free pass) so they don't dominate the "needs manual review" view, while
 * still showing up if their manifest genuinely looks unusual.
 */
export function scanInstalledExtensions(trustManager: TrustedExtensionsManager): ExtensionRiskProfile[] {
  const profiles: ExtensionRiskProfile[] = [];

  for (const ext of vscode.extensions.all) {
    if (ext.packageJSON?.isBuiltin || ext.id.startsWith('vscode.')) {
      continue; // skip VS Code's own built-in extensions
    }

    const pkg = ext.packageJSON || {};
    const activationEvents: string[] = pkg.activationEvents || [];
    const commands: any[] = pkg.contributes?.commands || [];
    const extensionKind: string[] = (ext.extensionKind !== undefined ? [String(ext.extensionKind)] : []) as string[];

    let score = 0;
    const factors: string[] = [];

    if (activationEvents.some((e) => BROAD_ACTIVATION_EVENTS.has(e))) {
      score += 20;
      factors.push('Activates broadly (e.g. on startup) rather than on a narrow event');
    }
    if (activationEvents.length === 0) {
      score += 5;
      factors.push('No declared activation events (implicitly always active in some hosts)');
    }
    if (pkg.contributes?.debuggers) {
      score += 15;
      factors.push('Contributes a debugger (can execute/inspect arbitrary processes)');
    }
    if (pkg.contributes?.terminal) {
      score += 10;
      factors.push('Contributes terminal integration');
    }
    if (JSON.stringify(pkg.contributes || {}).toLowerCase().includes('proxy')) {
      score += 10;
      factors.push('Manifest mentions proxy-related configuration');
    }
    if (pkg.main && !pkg.browser) {
      score += 5;
      factors.push('Node.js extension host access (full fs/net/child_process API surface)');
    }
    if (commands.length > 25) {
      score += 10;
      factors.push(`Large command surface (${commands.length} commands)`);
    }
    if (pkg.extensionDependencies?.length > 0) {
      score += 5;
      factors.push('Depends on other extensions');
    }

    const trusted = trustManager.isTrusted(ext.id);
    if (trusted) {
      score = Math.max(0, score - TRUSTED_SCORE_DISCOUNT);
      factors.push(`On trusted allowlist (−${TRUSTED_SCORE_DISCOUNT} points; still shown, not exempted)`);
    }
    score = Math.min(100, score);

    profiles.push({
      extensionId: ext.id,
      displayName: pkg.displayName || ext.id,
      isBuiltin: false,
      activationEvents,
      commandCount: commands.length,
      extensionKind,
      riskScore: score,
      riskFactors: factors,
      eventsSeen: 0,
      trusted,
      trustSource: trustManager.trustSource(ext.id)
    });
  }

  return profiles.sort((a, b) => b.riskScore - a.riskScore);
}
