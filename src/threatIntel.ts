import * as https from 'https';
import { ThreatIntelResult } from './types';

// A tiny, illustrative static watch-list that's always checked (it's free
// and instant) regardless of network availability. On its own it's a weak
// signal — see SOURCE_WEIGHTS — but it complements the network sources
// rather than only acting as a fallback when they're unreachable.
const STATIC_WATCHLIST_HOSTS = new Set<string>(['pastebin.com', 'ngrok.io', 'requestbin.com']);

// Relative weight each source contributes toward the 0-100 confidence
// score if it flags a host. These are illustrative, not calibrated against
// real precision/recall data — treat the resulting number as "how many
// independent signals agree," not a statistically validated probability.
const SOURCE_WEIGHTS: Record<string, number> = {
  URLhaus: 60,
  OpenPhish: 60,
  'static-list': 35
};

interface CacheEntry {
  result: ThreatIntelResult;
  expiresAt: number;
}

export interface ThreatIntelConfig {
  enabled: boolean;
  cacheTtlMinutes: number;
  timeoutMs: number;
}

const OPENPHISH_FEED_TTL_MS = 6 * 60 * 60 * 1000; // community feed only lists ~500 recent entries; 6h is plenty

/**
 * Checks a contacted host against multiple free, keyless threat-intel
 * sources and blends the results into a single confidence score rather
 * than trusting any one source outright:
 *   - URLhaus (abuse.ch) — malicious-host reports, queried live per host
 *   - OpenPhish community feed — a periodically-refreshed list of phishing
 *     URLs, checked by hostname membership
 *   - a small static watch-list — always checked, weakest signal alone
 * A host flagged by more sources gets a higher confidence score. Any
 * source that's unreachable is simply excluded from that check (not
 * treated as "clean"), so a network hiccup can't silently lower confidence.
 */
export class ThreatIntelService {
  private cache = new Map<string, CacheEntry>();
  private inFlight = new Map<string, Promise<ThreatIntelResult>>();

  private openPhishHosts = new Set<string>();
  private openPhishFetchedAt = 0;
  private openPhishFetchPromise: Promise<void> | undefined;

  constructor(private config: ThreatIntelConfig) {}

  updateConfig(config: ThreatIntelConfig): void {
    this.config = config;
  }

  private normalizeHost(hostOrHostPort: string): string {
    return hostOrHostPort.split(':')[0].trim().toLowerCase();
  }

  async checkHost(hostOrHostPort: string): Promise<ThreatIntelResult> {
    const host = this.normalizeHost(hostOrHostPort);

    if (!host || host === 'unknown-host') {
      return { checked: false, malicious: false, confidence: 0, sources: [], source: 'skipped' };
    }

    const cached = this.cache.get(host);
    if (cached && cached.expiresAt > Date.now()) {
      return { ...cached.result, source: `${cached.result.source} (cached)` };
    }

    const existing = this.inFlight.get(host);
    if (existing) {
      return existing;
    }

    const promise = this.evaluateHost(host).then((result) => {
      this.cache.set(host, { result, expiresAt: Date.now() + this.config.cacheTtlMinutes * 60_000 });
      this.inFlight.delete(host);
      return result;
    });

    this.inFlight.set(host, promise);
    return promise;
  }

  private async evaluateHost(host: string): Promise<ThreatIntelResult> {
    const checked: string[] = [];
    const flagged: string[] = [];
    const detailParts: string[] = [];
    let confidence = 0;

    // Static list: always checked, cheap, no network dependency.
    checked.push('static-list');
    if (STATIC_WATCHLIST_HOSTS.has(host)) {
      flagged.push('static-list');
      confidence += SOURCE_WEIGHTS['static-list'];
      detailParts.push('matched local illustrative watch-list (not a live feed)');
    }

    if (this.config.enabled) {
      try {
        const urlhaus = await this.queryUrlhaus(host);
        checked.push('URLhaus');
        if (urlhaus.flagged) {
          flagged.push('URLhaus');
          confidence += SOURCE_WEIGHTS.URLhaus;
          if (urlhaus.detail) {
            detailParts.push(urlhaus.detail);
          }
        }
      } catch {
        // URLhaus unreachable this round — excluded from `checked`, not
        // counted as a clean result.
      }

      try {
        const flaggedByOpenPhish = await this.checkOpenPhish(host);
        checked.push('OpenPhish');
        if (flaggedByOpenPhish) {
          flagged.push('OpenPhish');
          confidence += SOURCE_WEIGHTS.OpenPhish;
          detailParts.push('host appears in the OpenPhish community feed');
        }
      } catch {
        // feed unavailable this round — same treatment as URLhaus above.
      }
    }

    confidence = Math.min(100, confidence);
    const malicious = flagged.length > 0;

    return {
      checked: true,
      malicious,
      confidence,
      sources: flagged,
      source: malicious ? flagged.join(' + ') : `checked: ${checked.join(', ')}`,
      detail: detailParts.length ? detailParts.join('; ') : undefined,
      checkedAt: Date.now()
    };
  }

  /**
   * Queries abuse.ch's free URLhaus host-info endpoint. No API key required
   * for this basic lookup as of writing.
   */
  private queryUrlhaus(host: string): Promise<{ flagged: boolean; detail?: string }> {
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
                  flagged: urlCount > 0,
                  detail: urlCount > 0 ? `URLhaus: ${urlCount} malicious URL(s) reported for this host` : undefined
                });
              } else {
                resolve({ flagged: false });
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

  /**
   * Membership check against a periodically-refreshed OpenPhish community
   * feed (public, no API key). Throws if the feed can't be fetched at all,
   * which the caller treats as "source unavailable this round" rather than
   * "not flagged."
   */
  private async checkOpenPhish(host: string): Promise<boolean> {
    await this.ensureOpenPhishFeed();
    if (this.openPhishHosts.size === 0) {
      throw new Error('OpenPhish feed unavailable or empty');
    }
    return this.openPhishHosts.has(host);
  }

  private async ensureOpenPhishFeed(): Promise<void> {
    const fresh = this.openPhishHosts.size > 0 && Date.now() - this.openPhishFetchedAt < OPENPHISH_FEED_TTL_MS;
    if (fresh) {
      return;
    }
    if (this.openPhishFetchPromise) {
      return this.openPhishFetchPromise;
    }
    this.openPhishFetchPromise = this.fetchOpenPhishFeed()
      .then((hosts) => {
        this.openPhishHosts = hosts;
        this.openPhishFetchedAt = Date.now();
      })
      .finally(() => {
        this.openPhishFetchPromise = undefined;
      });
    return this.openPhishFetchPromise;
  }

  private fetchOpenPhishFeed(): Promise<Set<string>> {
    return new Promise((resolve, reject) => {
      const req = https.get(
        'https://openphish.com/feed.txt',
        { timeout: this.config.timeoutMs },
        (res) => {
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            const hosts = new Set<string>();
            for (const line of data.split('\n')) {
              const trimmed = line.trim();
              if (!trimmed) {
                continue;
              }
              try {
                hosts.add(new URL(trimmed).hostname.toLowerCase());
              } catch {
                // skip malformed line
              }
            }
            resolve(hosts);
          });
        }
      );
      req.on('timeout', () => req.destroy(new Error('OpenPhish feed fetch timed out')));
      req.on('error', reject);
    });
  }
}