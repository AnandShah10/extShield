import * as vscode from 'vscode';
import { ActivityEvent } from './types';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function dateStamp(ts: number): string {
  return new Date(ts).toISOString().slice(0, 10); // YYYY-MM-DD
}

/**
 * Persists the activity log to disk as newline-delimited JSON, one file per
 * day, under the extension's global storage directory. Uses
 * vscode.workspace.fs rather than Node's fs module so ExtShield's own log
 * writes never get captured by its own fs patches (which would otherwise
 * create a noisy feedback loop).
 */
export class LogStore {
  private logDir: vscode.Uri;
  private pending: ActivityEvent[] = [];
  private flushTimer: NodeJS.Timeout | undefined;

  constructor(context: vscode.ExtensionContext) {
    this.logDir = vscode.Uri.joinPath(context.globalStorageUri, 'activity-logs');
  }

  async init(): Promise<void> {
    try {
      await vscode.workspace.fs.createDirectory(this.logDir);
    } catch {
      // already exists or not creatable — subsequent writes will surface any real problem
    }
  }

  /** Queue events for a batched write instead of hitting disk on every single event. */
  queue(event: ActivityEvent): void {
    this.pending.push(event);
    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), 3000);
    }
  }

  async flush(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }
    if (this.pending.length === 0) {
      return;
    }
    const batch = this.pending;
    this.pending = [];

    const byFile = new Map<string, ActivityEvent[]>();
    for (const evt of batch) {
      const key = dateStamp(evt.timestamp);
      const arr = byFile.get(key) ?? [];
      arr.push(evt);
      byFile.set(key, arr);
    }

    for (const [stamp, events] of byFile) {
      const fileUri = vscode.Uri.joinPath(this.logDir, `activity-${stamp}.jsonl`);
      const lines = events.map((e) => JSON.stringify(e)).join('\n') + '\n';
      let existing = '';
      try {
        const bytes = await vscode.workspace.fs.readFile(fileUri);
        existing = textDecoder.decode(bytes);
      } catch {
        // file doesn't exist yet
      }
      await vscode.workspace.fs.writeFile(fileUri, textEncoder.encode(existing + lines));
    }
  }

  /**
   * Retroactively overwrites a single event's persisted record — used when
   * a threat-intel result arrives after the base event has already been
   * queued or flushed to disk. If the event is still sitting in the
   * pending (unflushed) batch, this just replaces it in place. Otherwise
   * it rewrites the specific line in that day's on-disk file, leaving
   * every other line untouched. A miss (event not found in either place —
   * e.g. its file was already pruned) is silently a no-op: the in-memory
   * dashboard copy is still correct, only the historical record misses the
   * update, which is a documented tradeoff, not a bug.
   */
  async updateEvent(event: ActivityEvent): Promise<void> {
    const pendingIdx = this.pending.findIndex((e) => e.id === event.id);
    if (pendingIdx !== -1) {
      this.pending[pendingIdx] = event;
      return;
    }

    const fileUri = vscode.Uri.joinPath(this.logDir, `activity-${dateStamp(event.timestamp)}.jsonl`);
    try {
      const bytes = await vscode.workspace.fs.readFile(fileUri);
      const lines = textDecoder.decode(bytes).split('\n').filter(Boolean);
      let changed = false;
      const rewritten = lines.map((line) => {
        try {
          const parsed = JSON.parse(line) as ActivityEvent;
          if (parsed.id === event.id) {
            changed = true;
            return JSON.stringify(event);
          }
        } catch {
          // malformed line — leave as-is
        }
        return line;
      });
      if (changed) {
        await vscode.workspace.fs.writeFile(fileUri, textEncoder.encode(rewritten.join('\n') + '\n'));
      }
    } catch {
      // file doesn't exist (already pruned, or never flushed under this
      // date) — nothing to update on disk.
    }
  }

  /** Loads up to `maxEntries` most recent events, newest-file-first. */
  async loadRecent(maxEntries: number): Promise<ActivityEvent[]> {
    const files = await this.listLogFiles();
    files.sort().reverse(); // newest date stamp first

    const collected: ActivityEvent[] = [];
    for (const file of files) {
      if (collected.length >= maxEntries) {
        break;
      }
      const uri = vscode.Uri.joinPath(this.logDir, file);
      try {
        const bytes = await vscode.workspace.fs.readFile(uri);
        const lines = textDecoder
          .decode(bytes)
          .split('\n')
          .filter(Boolean);
        for (const line of lines.reverse()) {
          try {
            collected.push(JSON.parse(line));
          } catch {
            // skip malformed line
          }
          if (collected.length >= maxEntries) {
            break;
          }
        }
      } catch {
        // skip unreadable file
      }
    }
    return collected.reverse().sort((a, b) => a.timestamp - b.timestamp);
  }

  async loadAll(): Promise<ActivityEvent[]> {
    return this.loadRecent(Number.MAX_SAFE_INTEGER);
  }

  private async listLogFiles(): Promise<string[]> {
    try {
      const entries = await vscode.workspace.fs.readDirectory(this.logDir);
      return entries
        .filter(([name, type]) => type === vscode.FileType.File && name.startsWith('activity-') && name.endsWith('.jsonl'))
        .map(([name]) => name);
    } catch {
      return [];
    }
  }

  /** Deletes daily log files older than `retentionDays`. */
  async pruneOldFiles(retentionDays: number): Promise<number> {
    if (retentionDays <= 0) {
      return 0; // 0 or negative means "keep forever"
    }
    const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
    const files = await this.listLogFiles();
    let deleted = 0;
    for (const file of files) {
      const match = /^activity-(\d{4}-\d{2}-\d{2})\.jsonl$/.exec(file);
      if (!match) {
        continue;
      }
      const fileTime = new Date(match[1] + 'T00:00:00Z').getTime();
      if (fileTime < cutoff) {
        try {
          await vscode.workspace.fs.delete(vscode.Uri.joinPath(this.logDir, file));
          deleted++;
        } catch {
          // ignore
        }
      }
    }
    return deleted;
  }

  get storageLocation(): string {
    return this.logDir.fsPath;
  }
}