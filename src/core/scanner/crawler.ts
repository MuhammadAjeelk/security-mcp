import { fetchPage } from './http-scanner.js';
import { discoverWellKnown } from './well-known.js';
import { runRecon } from './recon.js';
import { discoverContent } from './content-discovery.js';
import { extractJsEndpoints } from './js-endpoint-extractor.js';
import { discoverApiRoutes } from './api-route-discovery.js';
import { deriveFrontendCandidates, looksLikeApiHost } from './frontend-hints.js';
import { probeEndpointsPerRole } from './multi-role-prober.js';
import { validateTarget } from '../policy/target-policy.js';
import { getEnv } from '../../config/env.js';
import type {
  DiscoveredEndpoint,
  DiscoveredForm,
  ScanEvidence,
  ScanRequest,
  ScannedPage,
  TestAccount,
} from '../../types/scan.types.js';
import { AuditLogger } from '../logging/audit-logger.js';

const SCAN_TYPE_DEPTH: Record<ScanRequest['scanType'], number> = {
  quick: 0,
  standard: 1,
  deep: 3,
};

export interface CrawlOptions {
  request: ScanRequest;
  audit: AuditLogger;
}

export async function crawlTarget(opts: CrawlOptions): Promise<ScanEvidence> {
  const env = getEnv();
  const startedAt = new Date().toISOString();
  const requestedDepth = opts.request.maxDepth ?? SCAN_TYPE_DEPTH[opts.request.scanType];
  const maxDepth = Math.min(requestedDepth, env.SCAN_MAX_DEPTH);
  const maxRequests = env.SCAN_MAX_REQUESTS;

  const account = pickProbeAccount(opts.request.testAccounts);

  const root = validateTarget(opts.request.targetUrl, {
    extraAllowedHosts: opts.request.allowedHosts,
  });
  if (!root.allowed || !root.normalizedUrl) {
    throw new Error(`Target rejected by policy: ${root.reason}`);
  }

  const pages: ScannedPage[] = [];
  const headersByUrl: Record<string, Record<string, string>> = {};
  const cookiesByUrl: Record<string, string[]> = {};
  const forms: DiscoveredForm[] = [];
  const endpoints: DiscoveredEndpoint[] = [];
  const notes: string[] = [];

  // HTML bodies retained transiently so the JS-bundle extractor can find
  // <script src> tags. Not serialized into evidence.
  const htmlByUrl: Record<string, string> = {};

  const visited = new Set<string>();
  const queue: Array<{ url: string; depth: number }> = [{ url: root.normalizedUrl, depth: 0 }];

  let requestCount = 0;
  const rootOrigin = new URL(root.normalizedUrl).origin;

  while (queue.length > 0 && requestCount < maxRequests) {
    const next = queue.shift()!;
    if (visited.has(next.url)) continue;
    visited.add(next.url);

    let result;
    try {
      result = await fetchPage({
        url: next.url,
        depth: next.depth,
        extraAllowedHosts: opts.request.allowedHosts,
        account,
        session: opts.request.session,
        audit: opts.audit,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      notes.push(`Skipped ${next.url}: ${message}`);
      opts.audit.event('crawler.skip', { url: next.url, reason: message });
      continue;
    }

    requestCount += 1;
    pages.push(result.page);
    headersByUrl[result.page.finalUrl] = result.headers;
    if (result.setCookies.length > 0) {
      cookiesByUrl[result.page.finalUrl] = result.setCookies;
    }

    if (isHtml(result.headers['content-type'])) {
      htmlByUrl[result.page.finalUrl] = result.body;
    }

    if (next.depth < maxDepth && isHtml(result.headers['content-type'])) {
      const discovered = extractLinks(result.body, result.page.finalUrl);
      for (const link of discovered.links) {
        const linkUrl = safeUrl(link, result.page.finalUrl);
        if (!linkUrl) continue;
        if (new URL(linkUrl).origin !== rootOrigin) continue;
        if (!visited.has(linkUrl) && queue.length + requestCount < maxRequests) {
          queue.push({ url: linkUrl, depth: next.depth + 1 });
        }
      }
      for (const form of discovered.forms) {
        forms.push({ ...form, pageUrl: result.page.finalUrl });
      }
      for (const endpoint of discovered.endpoints) {
        endpoints.push(endpoint);
      }
    }
  }

  // Shared dedup ledger + merge helper for every post-crawl discovery phase.
  const seenEndpoints = new Set(endpoints.map((e) => `${e.method} ${e.url}`));
  const mergeEndpoints = (incoming: DiscoveredEndpoint[]) => {
    for (const e of incoming) {
      const key = `${e.method} ${e.url}`;
      if (seenEndpoints.has(key)) continue;
      seenEndpoints.add(key);
      endpoints.push(e);
    }
  };

  const deepish = opts.request.scanType !== 'quick';

  // Map well-known API doc/spec paths (Swagger/OpenAPI/GraphQL). Users often
  // publish a spec at /api/docs or /openapi.json and forget it is world-readable;
  // parsing it enumerates API operations the HTML crawl never links to.
  if (deepish && requestCount < maxRequests) {
    try {
      const wellKnown = await discoverWellKnown({
        rootUrl: root.normalizedUrl,
        account,
        session: opts.request.session,
        extraAllowedHosts: opts.request.allowedHosts,
        audit: opts.audit,
        maxRequests: maxRequests - requestCount,
      });
      requestCount += wellKnown.requestCount;
      mergeEndpoints(wellKnown.endpoints);
      notes.push(...wellKnown.notes);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      notes.push(`Well-known discovery skipped: ${message}`);
      opts.audit.event('well-known.error', { reason: message });
    }
  }

  // Passive recon: robots.txt + sitemap.xml. Cheap and high-signal — Disallow
  // entries point straight at paths the owner wanted hidden.
  if (deepish && requestCount < maxRequests) {
    try {
      const recon = await runRecon({
        rootUrl: root.normalizedUrl,
        account,
        session: opts.request.session,
        extraAllowedHosts: opts.request.allowedHosts,
        audit: opts.audit,
        maxRequests: maxRequests - requestCount,
      });
      requestCount += recon.requestCount;
      mergeEndpoints(recon.endpoints);
      notes.push(...recon.notes);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      notes.push(`Recon skipped: ${message}`);
      opts.audit.event('recon.error', { reason: message });
    }
  }

  // Pull API/route paths out of same-origin JS bundles (where SPA APIs hide).
  if (deepish && requestCount < maxRequests && Object.keys(htmlByUrl).length > 0) {
    try {
      const jsResult = await extractJsEndpoints({
        rootUrl: root.normalizedUrl,
        pages,
        htmlByUrl,
        account,
        session: opts.request.session,
        extraAllowedHosts: opts.request.allowedHosts,
        audit: opts.audit,
        maxRequests: maxRequests - requestCount,
      });
      requestCount += jsResult.requestCount;
      mergeEndpoints(jsResult.endpoints);
      notes.push(...jsResult.notes);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      notes.push(`JS endpoint extraction skipped: ${message}`);
      opts.audit.event('js-extract.error', { reason: message });
    }
  }

  // Undocumented API-route discovery — brute-force API resource names under
  // every prefix we have evidence for (the spec/crawl only show advertised
  // routes; legacy/internal/admin routes are usually undocumented). Runs after
  // the other discovery so it can derive prefixes from everything found so far.
  if (deepish && requestCount < maxRequests) {
    try {
      const apiRoutes = await discoverApiRoutes({
        rootUrl: root.normalizedUrl,
        knownEndpoints: endpoints,
        account,
        session: opts.request.session,
        extraAllowedHosts: opts.request.allowedHosts,
        audit: opts.audit,
        maxRequests: maxRequests - requestCount,
      });
      requestCount += apiRoutes.requestCount;
      mergeEndpoints(apiRoutes.endpoints);
      notes.push(...apiRoutes.notes);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      notes.push(`API-route discovery skipped: ${message}`);
      opts.audit.event('api-discovery.error', { reason: message });
    }
  }

  // Wordlist content discovery — opt-in (default on for deep scans) since it is
  // the heaviest phase. Brute-forces curated high-signal paths/files.
  const wantContentDiscovery =
    opts.request.includeContentDiscovery ?? opts.request.scanType === 'deep';
  if (wantContentDiscovery && requestCount < maxRequests) {
    try {
      const content = await discoverContent({
        rootUrl: root.normalizedUrl,
        account,
        session: opts.request.session,
        extraAllowedHosts: opts.request.allowedHosts,
        audit: opts.audit,
        maxRequests: maxRequests - requestCount,
      });
      requestCount += content.requestCount;
      mergeEndpoints(content.endpoints);
      notes.push(...content.notes);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      notes.push(`Content discovery skipped: ${message}`);
      opts.audit.event('content-discovery.error', { reason: message });
    }
  }

  const roleProbes = opts.request.testAccounts?.length
    ? await probeEndpointsPerRole({
        endpoints,
        accounts: opts.request.testAccounts,
        extraAllowedHosts: opts.request.allowedHosts,
        audit: opts.audit,
      })
    : undefined;

  // When the target is an API origin, the signup UI is elsewhere — surface
  // candidate frontend origins so the audit knows where to find registration.
  if (looksLikeApiHost(root.normalizedUrl)) {
    const candidates = deriveFrontendCandidates(root.normalizedUrl);
    if (candidates.length > 0) {
      notes.push(
        `Target looks like an API host; signup UI likely on the frontend. Candidate origins (verify scope + reachability): ${candidates.join(', ')}.`,
      );
    }
  }

  const completedAt = new Date().toISOString();

  return {
    targetUrl: root.normalizedUrl,
    scanType: opts.request.scanType,
    startedAt,
    completedAt,
    requestCount,
    pages,
    headers: headersByUrl,
    cookies: cookiesByUrl,
    forms,
    endpoints,
    notes,
    authenticatedRoles: opts.request.testAccounts?.map((a) => a.role),
    roleProbes,
  };
}

function pickProbeAccount(accounts?: TestAccount[]): TestAccount | undefined {
  if (!accounts || accounts.length === 0) return undefined;
  return accounts[0];
}

function isHtml(contentType: string | undefined): boolean {
  return !!contentType && contentType.toLowerCase().includes('html');
}

function safeUrl(href: string, base: string): string | null {
  try {
    const u = new URL(href, base);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    u.hash = '';
    return u.toString();
  } catch {
    return null;
  }
}

const LINK_RE = /<a\b[^>]*?\bhref\s*=\s*["']([^"']+)["'][^>]*>/gi;
const FORM_RE = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
const FORM_ACTION_RE = /\baction\s*=\s*["']([^"']*)["']/i;
const FORM_METHOD_RE = /\bmethod\s*=\s*["']([^"']*)["']/i;
const INPUT_NAME_RE = /<(?:input|select|textarea)\b[^>]*?\bname\s*=\s*["']([^"']+)["']/gi;
const FETCH_RE = /\b(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["']([^"']+)["']/gi;

function extractLinks(
  html: string,
  base: string,
): {
  links: string[];
  forms: Omit<DiscoveredForm, 'pageUrl'>[];
  endpoints: DiscoveredEndpoint[];
} {
  const links: string[] = [];
  const forms: Omit<DiscoveredForm, 'pageUrl'>[] = [];
  const endpoints: DiscoveredEndpoint[] = [];

  for (const match of html.matchAll(LINK_RE)) {
    if (match[1]) links.push(match[1]);
  }

  for (const match of html.matchAll(FORM_RE)) {
    const attrs = match[1] ?? '';
    const inner = match[2] ?? '';
    const action = attrs.match(FORM_ACTION_RE)?.[1];
    const method = (attrs.match(FORM_METHOD_RE)?.[1] ?? 'GET').toUpperCase();
    const fieldNames: string[] = [];
    for (const f of inner.matchAll(INPUT_NAME_RE)) {
      if (f[1]) fieldNames.push(f[1]);
    }
    forms.push({ action, method, fields: fieldNames });
  }

  for (const match of html.matchAll(FETCH_RE)) {
    const raw = match[1];
    if (!raw) continue;
    const resolved = safeUrl(raw, base);
    if (!resolved) continue;
    endpoints.push({ url: resolved, method: 'GET', source: 'inline-script' });
  }

  return { links, forms, endpoints };
}
