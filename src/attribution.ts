import * as path from 'path';

// Matches an installed extension's folder, e.g.:
//   /home/user/.vscode/extensions/publisher.name-1.2.3/out/extension.js
//   C:\Users\user\.vscode\extensions\publisher.name-1.2.3\dist\index.js
//   /root/.vscode-server/extensions/publisher.name-1.2.3/...
const EXTENSION_DIR_RE = /[/\\]\.vscode(?:-server)?[/\\]extensions[/\\]([^/\\]+)[/\\]/;

// Strips a trailing semver-ish version suffix from a folder name, e.g.
// "ms-python.python-2024.2.0" -> "ms-python.python"
const VERSION_SUFFIX_RE = /-\d+(\.\d+){1,3}[a-zA-Z0-9.-]*$/;

let selfExtensionPath: string | null = null;

/** Call once at activation so we can exclude our own frames from attribution. */
export function setSelfExtensionPath(extensionPath: string): void {
  selfExtensionPath = path.normalize(extensionPath);
}

export interface AttributionResult {
  extensionId: string | null;
  frame: string | null;
}

/**
 * Walks a captured Error stack and returns the first frame that lives inside
 * an installed extension's directory (skipping ExtShield's own frames and
 * generic Node/VS Code core frames). Best-effort only: extensions that use
 * worker threads, native addons, or the Web Extension host will not produce
 * attributable Node stack frames.
 */
export function attributeCaller(stack: string | undefined): AttributionResult {
  if (!stack) {
    return { extensionId: null, frame: null };
  }

  const lines = stack.split('\n').slice(1); // drop "Error" header line

  for (const line of lines) {
    const match = EXTENSION_DIR_RE.exec(line);
    if (!match) {
      continue;
    }

    const folderName = match[1];
    const fullPathMatch = /\((.*):\d+:\d+\)/.exec(line) || /at (.*):\d+:\d+/.exec(line);
    const framePath = fullPathMatch ? fullPathMatch[1] : line.trim();

    if (selfExtensionPath && framePath.includes(selfExtensionPath)) {
      continue; // it's us, keep looking
    }

    const extensionId = folderName.replace(VERSION_SUFFIX_RE, '');
    return { extensionId, frame: framePath };
  }

  return { extensionId: null, frame: null };
}

export function captureStack(): string | undefined {
  return new Error().stack;
}
