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
  source: string; // e.g. "URLhaus", "static-blocklist", "cache"
  detail?: string;
  checkedAt?: number;
}

export interface ActivityEvent {
  id: number;
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
