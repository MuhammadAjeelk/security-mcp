import { fetchPage } from './http-scanner.js';
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

  const roleProbes = opts.request.testAccounts?.length
    ? await probeEndpointsPerRole({
        endpoints,
        accounts: opts.request.testAccounts,
        extraAllowedHosts: opts.request.allowedHosts,
        audit: opts.audit,
      })
    : undefined;

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
