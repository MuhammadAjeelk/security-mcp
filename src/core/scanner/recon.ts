import { fetchPage } from './http-scanner.js';
import type { AuthSession, DiscoveredEndpoint, TestAccount } from '../../types/scan.types.js';
import { AuditLogger } from '../logging/audit-logger.js';

/**
 * Passive recon: read `robots.txt` and `sitemap.xml` from the target origin and
 * turn every path they reference into a discovered endpoint. `Disallow` entries
 * are gold — developers list exactly the paths they want hidden. All requests
 * are read-only GETs and bounded by the shared crawl budget.
 */
export interface ReconOptions {
  rootUrl: string;
  account?: TestAccount;
  session?: AuthSession;
  extraAllowedHosts?: string[];
  audit: AuditLogger;
  /** Hard cap on requests this routine may issue (shares the crawl budget). */
  maxRequests: number;
}

export interface ReconResult {
  endpoints: DiscoveredEndpoint[];
  notes: string[];
  requestCount: number;
}

export async function runRecon(opts: ReconOptions): Promise<ReconResult> {
  const origin = new URL(opts.rootUrl).origin;
  const endpoints: DiscoveredEndpoint[] = [];
  const notes: string[] = [];
  const sitemapUrls = new Set<string>([origin + '/sitemap.xml']);
  let requestCount = 0;

  // 1. robots.txt — paths + any Sitemap: directives it advertises.
  if (requestCount < opts.maxRequests) {
    const robots = await safeFetch(origin + '/robots.txt', opts);
    if (robots) {
      requestCount += 1;
      if (robots.status >= 200 && robots.status < 300 && robots.body.trim().length > 0) {
        const parsed = parseRobots(robots.body, origin);
        for (const p of parsed.paths) endpoints.push({ url: p, method: 'GET', source: 'recon' });
        for (const s of parsed.sitemaps) sitemapUrls.add(s);
        if (parsed.paths.length > 0) {
          notes.push(`robots.txt disclosed ${parsed.paths.length} path(s).`);
        }
      }
    }
  }

  // 2. sitemap(s) — <loc> entries.
  for (const sitemap of sitemapUrls) {
    if (requestCount >= opts.maxRequests) {
      notes.push('Recon stopped early: request budget exhausted.');
      break;
    }
    const res = await safeFetch(sitemap, opts);
    if (!res) continue;
    requestCount += 1;
    if (res.status < 200 || res.status >= 300) continue;
    const locs = parseSitemap(res.body, origin);
    for (const u of locs) endpoints.push({ url: u, method: 'GET', source: 'recon' });
    if (locs.length > 0) notes.push(`sitemap ${pathOf(sitemap)} listed ${locs.length} URL(s).`);
  }

  return { endpoints: dedupe(endpoints), notes, requestCount };
}

async function safeFetch(url: string, opts: ReconOptions) {
  try {
    const r = await fetchPage({
      url,
      depth: 0,
      extraAllowedHosts: opts.extraAllowedHosts,
      account: opts.account,
      session: opts.session,
      audit: opts.audit,
    });
    return { status: r.page.status, body: r.body };
  } catch (err) {
    opts.audit.event('recon.skip', {
      url,
      reason: err instanceof Error ? err.message : String(err),
    });
    return null;
  }
}

/** Extract Disallow/Allow paths and Sitemap directives from a robots.txt body. */
export function parseRobots(
  body: string,
  origin: string,
): { paths: string[]; sitemaps: string[] } {
  const paths: string[] = [];
  const sitemaps: string[] = [];
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const m = line.match(/^(disallow|allow|sitemap)\s*:\s*(.+)$/i);
    if (!m) continue;
    const directive = m[1]!.toLowerCase();
    const value = m[2]!.trim();
    if (directive === 'sitemap') {
      const abs = absolutize(value, origin);
      if (abs) sitemaps.push(abs);
      continue;
    }
    // Disallow/Allow — skip wildcards and the catch-all "/".
    if (!value || value === '/' || value.includes('*')) continue;
    const abs = absolutize(value, origin);
    if (abs && new URL(abs).origin === origin) paths.push(abs);
  }
  return { paths, sitemaps };
}

/** Extract <loc> URLs from a sitemap.xml body that belong to the target origin. */
export function parseSitemap(body: string, origin: string): string[] {
  const out: string[] = [];
  for (const m of body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) {
    const abs = absolutize(m[1]!, origin);
    if (abs && new URL(abs).origin === origin) out.push(abs);
  }
  return out;
}

function absolutize(value: string, origin: string): string | null {
  try {
    return new URL(value, origin).toString();
  } catch {
    return null;
  }
}

function pathOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

function dedupe(endpoints: DiscoveredEndpoint[]): DiscoveredEndpoint[] {
  const seen = new Set<string>();
  const out: DiscoveredEndpoint[] = [];
  for (const e of endpoints) {
    const key = `${e.method} ${e.url}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(e);
  }
  return out;
}
