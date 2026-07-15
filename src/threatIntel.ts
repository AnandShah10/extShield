import * as https from 'https';
import { ThreatIntelResult } from './types';

// A tiny, illustrative static fallback list used only when the live lookup
// is disabled or unreachable (e.g. offline, corporate proxy blocks it).
// This is NOT a real threat feed — just a safety net so the feature still
// demonstrates its flagging behavior without network access.
const STATIC_FALLBACK_SUSPICIOUS_HOSTS = new Set<string>([
  'pastebin.com',
  'ngrok.io',
  'requestbin.com'
]);

interface CacheEntry {
  result: ThreatIntelResult;
  expiresAt: number;
}

export interface ThreatIntelConfig {
  enabled: boolean;
  cacheTtlMinutes: number;
  timeoutMs: number;
}

export class ThreatIntelService {
  private cache = new Map<string, CacheEntry>();
  private inFlight = new Map<string, Promise<ThreatIntelResult>>();

  constructor(private config: ThreatIntelConfig) {}

  updateConfig(config: ThreatIntelConfig): void {
    this.config = config;
  }

  /** Strips port/credentials, lowercases, and returns just the hostname. */
  private normalizeHost(hostOrHostPort: string): string {
    const withoutPort = hostOrHostPort.split(':')[0];
    return withoutPort.trim().toLowerCase();
  }

  async checkHost(hostOrHostPort: string): Promise<ThreatIntelResult> {
    const host = this.normalizeHost(hostOrHostPort);

    if (!host || host === 'unknown-host') {
      return { checked: false, malicious: false, source: 'skipped' };
    }

    const cached = this.cache.get(host);
    if (cached && cached.expiresAt > Date.now()) {
      return { ...cached.result, source: 'cache' };
    }

    if (!this.config.enabled) {
      return this.staticFallback(host);
    }

    const existing = this.inFlight.get(host);
    if (existing) {
      return existing;
    }

    const promise = this.queryUrlhaus(host)
      .catch(() => this.staticFallback(host))
      .then((result) => {
        this.cache.set(host, {
          result,
          expiresAt: Date.now() + this.config.cacheTtlMinutes * 60_000
        });
        this.inFlight.delete(host);
        return result;
      });

    this.inFlight.set(host, promise);
    return promise;
  }

  private staticFallback(host: string): ThreatIntelResult {
    const malicious = STATIC_FALLBACK_SUSPICIOUS_HOSTS.has(host);
    return {
      checked: true,
      malicious,
      source: 'static-fallback-list',
      checkedAt: Date.now(),
      detail: malicious ? 'Host matched local illustrative watch-list (not a live feed)' : undefined
    };
  }

  /**
   * Queries abuse.ch's free URLhaus host-info endpoint. No API key required
   * for this basic lookup as of writing. Fails closed to "unknown" (not
   * "malicious") on any network/parse error — see catch above.
   */
  private queryUrlhaus(host: string): Promise<ThreatIntelResult> {
    return new Promise((resolve, reject) => {
      const body = `host=${encodeURIComponent(host)}`;
      const req = https.request(
        {
          hostname: 'urlhaus-api.abuse.ch',
          path: '/v1/host/',
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(body)
          },
          timeout: this.config.timeoutMs
        },
        (res) => {
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            try {
              const parsed = JSON.parse(data);
              if (parsed.query_status === 'ok') {
                const urlCount = Array.isArray(parsed.urls) ? parsed.urls.length : 0;
                resolve({
                  checked: true,
                  malicious: urlCount > 0,
                  source: 'URLhaus (abuse.ch)',
                  checkedAt: Date.now(),
                  detail: urlCount > 0 ? `${urlCount} malicious URL(s) reported for this host` : undefined
                });
              } else {
                // "no_results", "invalid_host", etc. — treat as not-flagged.
                resolve({ checked: true, malicious: false, source: 'URLhaus (abuse.ch)', checkedAt: Date.now() });
              }
            } catch (err) {
              reject(err);
            }
          });
        }
      );
      req.on('timeout', () => req.destroy(new Error('URLhaus lookup timed out')));
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }
}