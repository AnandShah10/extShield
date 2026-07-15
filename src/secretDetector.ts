// Lightweight, dependency-free heuristics for spotting likely-sensitive
// file paths and content. These are intentionally conservative pattern
// matches, not a full secret-scanning engine.

const SENSITIVE_PATH_PATTERNS: RegExp[] = [
  /\.env(\.[a-z]+)?$/i,
  /\.pem$/i,
  /\.key$/i,
  /\.pfx$/i,
  /id_rsa$/i,
  /id_ed25519$/i,
  /\.ssh[/\\]/i,
  /credentials(\.json)?$/i,
  /\.aws[/\\]credentials$/i,
  /\.netrc$/i,
  /secrets?\.(json|ya?ml|toml)$/i,
  /\.npmrc$/i,
  /\.pypirc$/i,
  /keychain/i,
  /\.git-credentials$/i
];

const CONTENT_SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'AWS Access Key ID', re: /AKIA[0-9A-Z]{16}/ },
  { name: 'Generic API key assignment', re: /(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/i },
  { name: 'Private key block', re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'Slack token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/ },
  { name: 'GitHub token', re: /gh[pousr]_[A-Za-z0-9]{36,}/ },
  { name: 'JWT-looking string', re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ }
];

export function isSensitivePath(filePath: string): boolean {
  return SENSITIVE_PATH_PATTERNS.some((re) => re.test(filePath));
}

export function scanContentForSecrets(content: string): string[] {
  const hits: string[] = [];
  // Cap scan size so we never do heavy regex work on huge files.
  const sample = content.length > 200_000 ? content.slice(0, 200_000) : content;
  for (const { name, re } of CONTENT_SECRET_PATTERNS) {
    if (re.test(sample)) {
      hits.push(name);
    }
  }
  return hits;
}
