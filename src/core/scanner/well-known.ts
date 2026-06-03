import { fetchPage } from './http-scanner.js';
import type { AuthSession, DiscoveredEndpoint, TestAccount } from '../../types/scan.types.js';
import { AuditLogger } from '../logging/audit-logger.js';

/**
 * Curated list of well-known paths that disclose API surface: OpenAPI/Swagger
 * specifications, interactive doc UIs, and common API roots. Every probe is a
 * read-only GET. Hitting these is how an attacker maps the API quickly — users
 * frequently publish a spec at `/api/docs` or `/openapi.json` and forget it is
 * world-readable.
 */
export const WELL_KNOWN_PATHS: readonly string[] = Object.freeze([
  // Interactive documentation UIs
  '/api/docs',
  '/api/doc',
  '/docs',
  '/swagger',
  '/swagger-ui',
  '/swagger-ui.html',
  '/swagger/index.html',
  '/redoc',
  '/graphql',
  '/graphiql',
  // Machine-readable specifications
  '/openapi.json',
  '/openapi.yaml',
  '/swagger.json',
  '/swagger/v1/swagger.json',
  '/api-docs',
  '/api/swagger.json',
  '/api/openapi.json',
  '/v2/api-docs',
  '/v3/api-docs',
  '/docs/swagger.json',
  '/.well-known/openapi.json',
]);

const SPEC_CONTENT_RE = /("openapi"|"swagger"|"paths"\s*:|openapi:|swagger:)/i;

export interface WellKnownOptions {
  rootUrl: string;
  account?: TestAccount;
  session?: AuthSession;
  extraAllowedHosts?: string[];
  audit: AuditLogger;
  /** Hard cap on requests this routine may issue (shares the crawl budget). */
  maxRequests: number;
}

export interface WellKnownResult {
  endpoints: DiscoveredEndpoint[];
  notes: string[];
  requestCount: number;
}

/**
 * Probe well-known API documentation/spec paths and, for any that return a
 * usable OpenAPI/Swagger document, parse out the declared operations so they
 * land in the attack surface. Read-only and budget-bounded.
 */
export async function discoverWellKnown(opts: WellKnownOptions): Promise<WellKnownResult> {
  const origin = new URL(opts.rootUrl).origin;
  const endpoints: DiscoveredEndpoint[] = [];
  const notes: string[] = [];
  let requestCount = 0;

  for (const path of WELL_KNOWN_PATHS) {
    if (requestCount >= opts.maxRequests) {
      notes.push('Well-known probing stopped early: request budget exhausted.');
      break;
    }
    const url = origin + path;
    let result;
    try {
      result = await fetchPage({
        url,
        depth: 0,
        extraAllowedHosts: opts.extraAllowedHosts,
        account: opts.account,
        session: opts.session,
        audit: opts.audit,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      opts.audit.event('well-known.skip', { url, reason: message });
      continue;
    }
    requestCount += 1;

    if (result.page.status < 200 || result.page.status >= 400) continue;

    // The doc/spec endpoint itself is reachable — record it.
    endpoints.push({ url, method: 'GET', source: 'well-known' });

    const looksLikeSpec =
      isJson(result.headers['content-type']) || SPEC_CONTENT_RE.test(result.body);
    if (!looksLikeSpec) continue;

    const parsed = parseOpenApiEndpoints(result.body, origin);
    if (parsed.length > 0) {
      notes.push(`Parsed ${parsed.length} operation(s) from API spec at ${path}.`);
      endpoints.push(...parsed);
    }
  }

  return { endpoints, notes, requestCount };
}

function isJson(contentType: string | undefined): boolean {
  return !!contentType && /json/i.test(contentType);
}

const HTTP_METHODS = new Set(['get', 'put', 'post', 'delete', 'patch', 'head', 'options']);

/**
 * Extract concrete endpoint URLs from an OpenAPI 3 / Swagger 2 JSON document.
 * Resolves the server/basePath prefix against the target origin. YAML specs are
 * skipped (no parser dependency) — the doc URL itself is still recorded.
 */
export function parseOpenApiEndpoints(body: string, origin: string): DiscoveredEndpoint[] {
  let doc: unknown;
  try {
    doc = JSON.parse(body);
  } catch {
    return [];
  }
  if (!doc || typeof doc !== 'object') return [];
  const spec = doc as Record<string, unknown>;
  const paths = spec['paths'];
  if (!paths || typeof paths !== 'object') return [];

  const prefix = resolveBasePrefix(spec, origin);
  const out: DiscoveredEndpoint[] = [];

  for (const [rawPath, ops] of Object.entries(paths as Record<string, unknown>)) {
    if (!rawPath.startsWith('/')) continue;
    const url = prefix + rawPath;
    const methods =
      ops && typeof ops === 'object'
        ? Object.keys(ops).filter((m) => HTTP_METHODS.has(m.toLowerCase()))
        : [];
    if (methods.length === 0) {
      out.push({ url, method: 'GET', source: 'api-spec' });
      continue;
    }
    for (const m of methods) {
      out.push({ url, method: m.toUpperCase(), source: 'api-spec' });
    }
  }
  return out;
}

/** Resolve the API base prefix (OpenAPI3 `servers[0].url` or Swagger2 `basePath`). */
function resolveBasePrefix(spec: Record<string, unknown>, origin: string): string {
  // OpenAPI 3: servers[0].url (may be absolute or a relative path).
  const servers = spec['servers'];
  if (Array.isArray(servers) && servers.length > 0) {
    const first = servers[0] as { url?: unknown };
    if (typeof first?.url === 'string' && first.url.length > 0) {
      try {
        const resolved = new URL(first.url, origin);
        if (resolved.origin === origin) {
          return origin + resolved.pathname.replace(/\/$/, '');
        }
      } catch {
        // fall through
      }
    }
  }
  // Swagger 2: basePath.
  const basePath = spec['basePath'];
  if (typeof basePath === 'string' && basePath.startsWith('/')) {
    return origin + basePath.replace(/\/$/, '');
  }
  return origin;
}
