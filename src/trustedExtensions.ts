import * as vscode from 'vscode';

const STORAGE_KEY = 'extshield.trustedExtensions.v1';

// A small, conservative starter list of widely-used, well-established
// publishers/extensions. This is a convenience default, not a security
// endorsement — it only means "don't nag the user to configure a policy
// for this extension by default." Users can add/remove freely.
const BUILTIN_TRUSTED_IDS: string[] = [
  'ms-python.python',
  'ms-python.vscode-pylance',
  'ms-vscode.cpptools',
  'ms-dotnettools.csharp',
  'ms-azuretools.vscode-docker',
  'ms-vscode-remote.remote-ssh',
  'ms-vscode-remote.remote-containers',
  'ms-vscode-remote.remote-wsl',
  'dbaeumer.vscode-eslint',
  'esbenp.prettier-vscode',
  'github.copilot',
  'github.copilot-chat',
  'github.vscode-pull-request-github',
  'golang.go',
  'rust-lang.rust-analyzer',
  'redhat.java',
  'vscjava.vscode-java-pack',
  'eamodio.gitlens',
  'ms-vscode.powershell',
  'hashicorp.terraform',
  'timonwong.shellcheck'
];

export class TrustedExtensionsManager {
  private userAdded = new Set<string>();
  private userRemovedFromBuiltin = new Set<string>();

  constructor(private context: vscode.ExtensionContext) {
    // If the user has VS Code Settings Sync turned on, this key (and
    // therefore trust decisions) syncs across their machines automatically
    // with zero extra effort — this is a real, built-in VS Code mechanism,
    // not something ExtShield implements itself. exportAsJson/importFromJson
    // below cover the case where Settings Sync isn't in use, or the user
    // wants to hand a curated list to a teammate.
    try {
      context.globalState.setKeysForSync([STORAGE_KEY]);
    } catch {
      // setKeysForSync can be unavailable in some hosts; trust still works
      // locally, it just won't participate in Settings Sync.
    }

    const stored = context.globalState.get<{ added: string[]; removed: string[] }>(STORAGE_KEY, {
      added: [],
      removed: []
    });
    this.userAdded = new Set(stored.added);
    this.userRemovedFromBuiltin = new Set(stored.removed);
  }

  private async persist(): Promise<void> {
    await this.context.globalState.update(STORAGE_KEY, {
      added: [...this.userAdded],
      removed: [...this.userRemovedFromBuiltin]
    });
  }

  isTrusted(extensionId: string): boolean {
    if (this.userAdded.has(extensionId)) {
      return true;
    }
    if (BUILTIN_TRUSTED_IDS.includes(extensionId) && !this.userRemovedFromBuiltin.has(extensionId)) {
      return true;
    }
    return false;
  }

  trustSource(extensionId: string): 'builtin-list' | 'user-added' | undefined {
    if (this.userAdded.has(extensionId)) {
      return 'user-added';
    }
    if (BUILTIN_TRUSTED_IDS.includes(extensionId) && !this.userRemovedFromBuiltin.has(extensionId)) {
      return 'builtin-list';
    }
    return undefined;
  }

  async addTrusted(extensionId: string): Promise<void> {
    this.userAdded.add(extensionId);
    this.userRemovedFromBuiltin.delete(extensionId);
    await this.persist();
  }

  async removeTrusted(extensionId: string): Promise<void> {
    this.userAdded.delete(extensionId);
    if (BUILTIN_TRUSTED_IDS.includes(extensionId)) {
      this.userRemovedFromBuiltin.add(extensionId);
    }
    await this.persist();
  }

  getAllTrusted(): string[] {
    const all = new Set(BUILTIN_TRUSTED_IDS.filter((id) => !this.userRemovedFromBuiltin.has(id)));
    for (const id of this.userAdded) {
      all.add(id);
    }
    return [...all].sort();
  }

  /**
   * Serializes the user's *additions and removals* (not the built-in list
   * itself, which ships with the extension) so it can be shared with a
   * teammate or moved to a machine without Settings Sync enabled.
   */
  exportAsJson(): string {
    return JSON.stringify(
      {
        extshieldTrustedExtensionsExport: 1,
        exportedAt: new Date().toISOString(),
        added: [...this.userAdded].sort(),
        removedFromBuiltin: [...this.userRemovedFromBuiltin].sort()
      },
      null,
      2
    );
  }

  /**
   * Merges an exported list into the current one (additive — this never
   * removes trust the user already granted locally, it only adds to it,
   * plus re-applies any explicit removals-from-builtin the export
   * contained). Returns how many entries actually changed something, so
   * the caller can report a meaningful count.
   */
  async importFromJson(json: string): Promise<{ added: number; removed: number }> {
    let parsed: any;
    try {
      parsed = JSON.parse(json);
    } catch {
      throw new Error('Not valid JSON.');
    }
    const added: string[] = Array.isArray(parsed?.added) ? parsed.added.filter((x: unknown) => typeof x === 'string') : [];
    const removed: string[] = Array.isArray(parsed?.removedFromBuiltin)
      ? parsed.removedFromBuiltin.filter((x: unknown) => typeof x === 'string')
      : [];

    let addedCount = 0;
    let removedCount = 0;
    for (const id of added) {
      if (!this.userAdded.has(id)) {
        this.userAdded.add(id);
        this.userRemovedFromBuiltin.delete(id);
        addedCount++;
      }
    }
    for (const id of removed) {
      if (BUILTIN_TRUSTED_IDS.includes(id) && !this.userRemovedFromBuiltin.has(id)) {
        this.userRemovedFromBuiltin.add(id);
        removedCount++;
      }
    }
    if (addedCount || removedCount) {
      await this.persist();
    }
    return { added: addedCount, removed: removedCount };
  }
}