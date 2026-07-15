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
}