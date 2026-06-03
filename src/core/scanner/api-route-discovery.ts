import { fetchPage } from './http-scanner.js';
import { sendRequest } from './http-request.js';
import { getEnv } from '../../config/env.js';
import type { AuthSession, DiscoveredEndpoint, TestAccount } from '../../types/scan.types.js';
import { AuditLogger } from '../logging/audit-logger.js';

/**
 * Discover UNDOCUMENTED API routes. The OpenAPI spec and HTML crawl only show
 * what the app advertises; the dangerous routes (legacy, internal, debug, admin)
 * are often the ones nobody documented. This brute-forces a curated list of API
 * resource names under every API prefix we have evidence for, and treats a
 * non-404 response — INCLUDING 401/403/405 — as proof the route exists.
 *
 * Read-only GETs (+ a bounded OPTIONS per hit to learn allowed methods). Hard
 * capped by SCAN_API_DISCOVERY_MAX and the shared crawl budget.
 */

/** High-signal API resource names worth probing under each prefix. */
const API_RESOURCES: readonly string[] = Object.freeze([
  'users', 'user', 'accounts', 'account', 'me', 'profile', 'profiles', 'admin', 'admins',
  'auth', 'login', 'logout', 'register', 'signup', 'password', 'roles', 'role', 'permissions',
  'groups', 'orders', 'order', 'payments', 'transactions', 'invoices', 'subscriptions', 'billing',
  'checkout', 'products', 'items', 'files', 'file', 'upload', 'uploads', 'download', 'export',
  'import', 'reports', 'report', 'notifications', 'messages', 'comments', 'search', 'settings',
  'config', 'health', 'status', 'metrics', 'debug', 'internal', 'webhooks', 'tokens', 'sessions',
  'keys', 'api-keys', 'audit', 'logs', 'events', 'jobs', 'tasks', 'organizations', 'orgs',
  'tenants', 'teams', 'projects', 'dashboard', 'verify', 'verify-email', 'reset-password',
]);

/** Prefixes always worth trying even with zero prior evidence. */
const DEFAULT_PREFIXES: readonly string[] = Object.freeze([
  '', '/api', '/api/v1', '/api/v2', '/v1', '/v2', '/rest', '/internal', '/admin',
]);

export interface ApiRouteDiscoveryOptions {
  rootUrl: string;
  knownEndpoints: DiscoveredEndpoint[];
  account?: TestAccount;
  session?: AuthSession;
  extraAllowedHosts?: string[];
  audit: AuditLogger;
  /** Hard cap on requests this routine may issue (shares the crawl budget). */
  maxRequests: number;
}

export interface ApiRouteDiscoveryResult {
  endpoints: DiscoveredEndpoint[];
  notes: string[];
  requestCount: number;
}

const DEAD_STATUSES = new Set([404, 410]);

export async function discoverApiRoutes(
  opts: ApiRouteDiscoveryOptions,
): Promise<ApiRouteDiscoveryResult> {
  const env = getEnv();
  const origin = new URL(opts.rootUrl).origin;
  const endpoints: DiscoveredEndpoint[] = [];
  const notes: string[] = [];
  let requestCount = 0;

  const prefixes = derivePrefixes(opts.knownEndpoints, origin);
  const budget = Math.min(opts.maxRequests, env.SCAN_API_DISCOVERY_MAX);
  opts.audit.event('api-discovery.start', { prefixes: [...prefixes], budget });

  // Per-prefix soft-404 baseline (SPA catch-alls return 200 for everything).
  const baseline = new Map<string, { status: number; length: number }>();

  const seen = new Set<string>();
  outer: for (const prefix of prefixes) {
    if (requestCount >= budget) break;
    // Establish this prefix's not-found baseline with one random path.
    if (!baseline.has(prefix) && requestCount < budget) {
      const probe = await safeGet(`${origin}${prefix}/smcp-nope-${prefix.length}xz9`, opts);
      requestCount += 1;
      if (probe) baseline.set(prefix, { status: probe.status, length: probe.body.length });
    }
    const base = baseline.get(prefix);

    for (const resource of API_RESOURCES) {
      if (requestCount >= budget) break outer;
      const path = `${prefix}/${resource}`.replace(/\/+/g, '/');
      const url = origin + path;
      if (seen.has(url)) continue;
      seen.add(url);

      const res = await safeGet(url, opts);
      requestCount += 1;
      if (!res) continue;
      if (DEAD_STATUSES.has(res.status)) continue;
      // Skip SPA soft-404 (same status + near-identical length as baseline).
      if (
        base &&
        base.status === res.status &&
        Math.abs(base.length - res.body.length) < 16 &&
        res.status >= 200 &&
        res.status < 300
      ) {
        continue;
      }

      endpoints.push({ url, method: 'GET', source: 'api-discovery' });
      // 401/403/405 are the most interesting: the route EXISTS but is gated.
      if (res.status === 401 || res.status === 403 || res.status === 405) {
        notes.push(`Undocumented protected route ${path} → ${res.status} (exists, gated).`);
      }

      // Learn the allowed methods so vuln testing can hit the real verbs.
      if (requestCount < budget) {
        const allow = await optionsAllow(url, opts);
        requestCount += 1;
        for (const m of allow) {
          if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') continue;
          endpoints.push({ url, method: m, source: 'api-discovery' });
        }
      }
    }
  }

  notes.push(`API-route discovery probed ${requestCount} candidates; found ${endpoints.length} route entries.`);
  opts.audit.event('api-discovery.done', { requestCount, found: endpoints.length });
  return { endpoints, notes, requestCount };
}

/**
 * Build the set of API prefixes to brute-force: the defaults plus any prefix we
 * can infer from already-discovered endpoints (e.g. seeing /api/v3/users tells
 * us /api/v3 is a live base).
 */
function derivePrefixes(known: DiscoveredEndpoint[], origin: string): Set<string> {
  const prefixes = new Set<string>(DEFAULT_PREFIXES);
  for (const e of known) {
    let path: string;
    try {
      const u = new URL(e.url, origin);
      if (u.origin !== origin) continue;
      path = u.pathname;
    } catch {
      continue;
    }
    const segs = path.split('/').filter(Boolean);
    // Collect the leading API-ish prefix: up to an `api`/`vN`/`rest` segment.
    const acc: string[] = [];
    for (const seg of segs.slice(0, 3)) {
      if (/^(api|rest|internal|admin|v\d+)$/i.test(seg)) {
        acc.push(seg);
        prefixes.add('/' + acc.join('/'));
      } else if (acc.length > 0) {
        break;
      } else {
        break;
      }
    }
  }
  return prefixes;
}

async function safeGet(
  url: string,
  opts: ApiRouteDiscoveryOptions,
): Promise<{ status: number; body: string } | null> {
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
  } catch {
    return null;
  }
}

async function optionsAllow(url: string, opts: ApiRouteDiscoveryOptions): Promise<string[]> {
  try {
    const r = await sendRequest({
      url,
      method: 'OPTIONS',
      account: opts.account,
      session: opts.session,
      extraAllowedHosts: opts.extraAllowedHosts,
    });
    const allow = r.headers['allow'] || r.headers['access-control-allow-methods'];
    if (!allow) return [];
    return allow
      .split(',')
      .map((m) => m.trim().toUpperCase())
      .filter((m) => /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(m));
  } catch {
    return [];
  }
}
