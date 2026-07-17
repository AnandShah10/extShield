export type EventKind =
  | 'fs.read'
  | 'fs.write'
  | 'fs.delete'
  | 'fs.readdir'
  | 'net.request'
  | 'child.exec'
  | 'env.read';

export type RiskLevel = 'low' | 'medium' | 'high';

export interface ThreatIntelResult {
  checked: boolean;
  malicious: boolean;
  confidence: number; // 0-100, blended weight of every source that flagged the host
  sources: string[]; // names of sources that flagged it; empty if clean or unchecked
  source: string; // human-readable summary (e.g. "URLhaus + OpenPhish", "cache"), kept for display convenience
  detail?: string;
  checkedAt?: number;
}

export interface ActivityEvent {
  id: string; // globally unique (not just per-session) so delayed updates can find the right persisted record
  timestamp: number;
  extensionId: string | null; // null = could not attribute (likely VS Code core or ExtShield itself)
  kind: EventKind;
  target: string; // file path, URL/host, env var name, or command
  risk: RiskLevel;
  blocked: boolean;
  reason?: string; // why it was flagged (e.g. matched secret pattern, policy violation)
  threatIntel?: ThreatIntelResult; // populated asynchronously for net.request events
}

export interface ExtensionPolicy {
  extensionId: string;
  allowedPathPrefixes: string[]; // if empty, all paths allowed (no restriction configured)
  blockNetwork: boolean;
  blockChildProcess: boolean;
}

export interface ExtensionRiskProfile {
  extensionId: string;
  displayName: string;
  isBuiltin: boolean;
  activationEvents: string[];
  commandCount: number;
  extensionKind: string[];
  riskScore: number; // 0-100 heuristic score
  riskFactors: string[];
  eventsSeen: number;
  trusted: boolean;
  trustSource?: 'builtin-list' | 'user-added';
}

export interface IsolationSuggestion {
  extensionId: string;
  canSuggest: boolean; // false if no remote/container context is available to isolate into
  currentHost: 'local' | 'remote/container' | 'unknown';
  suggestedExtensionKind: 'workspace' | 'ui';
  rationale: string;
}
