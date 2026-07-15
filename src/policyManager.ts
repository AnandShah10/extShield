import * as vscode from 'vscode';
import * as path from 'path';
import { ExtensionPolicy } from './types';

const STORAGE_KEY = 'extshield.policies.v1';

export class PolicyManager {
  private policies = new Map<string, ExtensionPolicy>();

  constructor(private context: vscode.ExtensionContext) {
    const stored = context.globalState.get<ExtensionPolicy[]>(STORAGE_KEY, []);
    for (const p of stored) {
      this.policies.set(p.extensionId, p);
    }
  }

  private async persist(): Promise<void> {
    await this.context.globalState.update(STORAGE_KEY, [...this.policies.values()]);
  }

  getPolicy(extensionId: string): ExtensionPolicy | undefined {
    return this.policies.get(extensionId);
  }

  getAllPolicies(): ExtensionPolicy[] {
    return [...this.policies.values()];
  }

  async setPolicy(policy: ExtensionPolicy): Promise<void> {
    this.policies.set(policy.extensionId, policy);
    await this.persist();
  }

  async removePolicy(extensionId: string): Promise<void> {
    this.policies.delete(extensionId);
    await this.persist();
  }

  /** Returns true if the given file path is allowed under the extension's policy. */
  isPathAllowed(extensionId: string | null, filePath: string): boolean {
    if (!extensionId) {
      return true; // can't attribute -> can't enforce, fail open (see README)
    }
    const policy = this.policies.get(extensionId);
    if (!policy || policy.allowedPathPrefixes.length === 0) {
      return true; // no restriction configured
    }
    const normalized = path.normalize(filePath);
    return policy.allowedPathPrefixes.some((prefix) => normalized.startsWith(path.normalize(prefix)));
  }

  isNetworkAllowed(extensionId: string | null): boolean {
    if (!extensionId) {
      return true;
    }
    const policy = this.policies.get(extensionId);
    return !policy?.blockNetwork;
  }

  isChildProcessAllowed(extensionId: string | null): boolean {
    if (!extensionId) {
      return true;
    }
    const policy = this.policies.get(extensionId);
    return !policy?.blockChildProcess;
  }
}
