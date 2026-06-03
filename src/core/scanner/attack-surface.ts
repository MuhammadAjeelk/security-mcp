import { PROMPT_REGISTRY } from '../prompt-engine/prompt-registry.js';
import type {
  AttackSurface,
  AttackSurfaceEndpoint,
  AttackSurfaceGoal,
  DiscoveredForm,
  ScanEvidence,
} from '../../types/scan.types.js';

/**
 * Deterministically derive the attack-surface map from collected evidence.
 *
 * This is the only piece of the expert-audit feature that runs server-side: it
 * turns the crawl evidence into a structured inventory plus a per-endpoint list
 * of *applicable* security goals (prompt-module ids). It performs NO network
 * I/O and is pure given the same evidence, so reports are reproducible.
 */
export function buildAttackSurface(evidence: ScanEvidence): AttackSurface {
  const goalCatalog: AttackSurfaceGoal[] = PROMPT_REGISTRY.map((p) => ({
    id: p.id,
    title: p.title,
    category: p.category,
  }));

  const formsByUrl = indexFormsByActionUrl(evidence.forms, evidence.targetUrl);
  const authGatedUrls = collectAuthGatedUrls(evidence);

  const endpoints: AttackSurfaceEndpoint[] = evidence.endpoints.map((e) => {
    const hasQueryParams = urlHasQuery(e.url);
    const hasPathId = pathHasId(e.url);
    const form = formsByUrl.get(normalizeUrl(e.url));
    const hasForm = !!form;
    const isUpload = !!form && formLooksLikeUpload(form);
    const looksAdmin = pathLooksAdmin(e.url);
    const authGated = authGatedUrls.has(normalizeUrl(e.url));
    const isApiLike = endpointLooksApi(e.url, e.method);

    const flags = {
      hasQueryParams,
      hasPathId,
      authGated,
      hasForm,
      isUpload,
      looksAdmin,
      isApiLike,
    };
    return {
      url: e.url,
      method: e.method,
      ...flags,
      applicableGoals: applicableGoalIds(goalCatalog, flags),
    };
  });

  return {
    generatedAt: evidence.completedAt || evidence.startedAt,
    totalEndpoints: endpoints.length,
    withParams: endpoints.filter((e) => e.hasQueryParams).length,
    withPathId: endpoints.filter((e) => e.hasPathId).length,
    authGated: endpoints.filter((e) => e.authGated).length,
    uploads: endpoints.filter((e) => e.isUpload).length,
    adminLike: endpoints.filter((e) => e.looksAdmin).length,
    apiLike: endpoints.filter((e) => e.isApiLike).length,
    forms: evidence.forms.length,
    endpoints,
    goalCatalog,
  };
}

interface EndpointFlags {
  hasQueryParams: boolean;
  hasPathId: boolean;
  authGated: boolean;
  hasForm: boolean;
  isUpload: boolean;
  looksAdmin: boolean;
  isApiLike: boolean;
}

/**
 * Map endpoint flags to the prompt-module categories that are worth running
 * against it. Goals with no category-specific gate (headers, config,
 * infrastructure) are always applicable — they describe the whole target.
 */
function applicableGoalIds(catalog: AttackSurfaceGoal[], flags: EndpointFlags): string[] {
  // An API-like endpoint (/api, /graphql, bodied method) accepts input through
  // its body even when the crawled URL carries no `?query`. Treating it as
  // input-bearing is what stops injection/API checks being silently skipped on
  // JSON/REST APIs — the single biggest coverage gap in the old logic.
  const hasInput = flags.hasQueryParams || flags.hasForm || flags.isApiLike;
  return catalog
    .filter((g) => {
      switch (g.category) {
        case 'injection':
        case 'input-validation':
          return hasInput;
        case 'access-control':
        case 'authorization':
        case 'multi-tenant':
          return flags.hasPathId || flags.authGated || flags.isApiLike;
        case 'auth':
          return flags.authGated || flags.hasForm || flags.isApiLike;
        case 'api':
          return hasInput || flags.hasPathId;
        case 'business-logic':
        case 'payment':
          return flags.hasForm || flags.hasQueryParams || flags.isApiLike;
        case 'files':
          return flags.isUpload || flags.hasPathId;
        // headers / configuration / infrastructure / reporting apply target-wide
        default:
          return true;
      }
    })
    .map((g) => g.id);
}

/**
 * True when the endpoint is a programmatic API surface: a recognizable API path
 * prefix, GraphQL, or any state-changing/bodied HTTP method. These accept input
 * via the request body, so input-driven goals apply even without a query string.
 */
function endpointLooksApi(url: string, method: string): boolean {
  const m = method.toUpperCase();
  if (m === 'POST' || m === 'PUT' || m === 'PATCH' || m === 'DELETE') return true;
  const path = safePath(url).toLowerCase();
  return /(^\/api(\/|$)|\/graphql|\/rest(\/|$)|^\/v\d+(\/|$)|\/v\d+\/)/.test(path);
}

function urlHasQuery(url: string): boolean {
  try {
    return [...new URL(url, 'http://placeholder.local').searchParams.keys()].length > 0;
  } catch {
    return url.includes('?');
  }
}

function pathHasId(url: string): boolean {
  const path = safePath(url);
  // Concrete ids (numeric/hex/UUID) or OpenAPI template params (`{id}`, raw or
  // percent-encoded as `%7Bid%7D` once normalized through the URL constructor).
  return (
    /\/(\d+|[0-9a-f]{8,}|[0-9a-f-]{16,})(\/|$)/i.test(path) ||
    /(\{[^/}]+\}|%7b[^/]*%7d)/i.test(path)
  );
}

function pathLooksAdmin(url: string): boolean {
  const path = safePath(url).toLowerCase();
  return /(\/admin|\/internal|\/debug|\/actuator|\/_|\/management|\/console|\/dashboard)/.test(path);
}

function formLooksLikeUpload(form: DiscoveredForm): boolean {
  if (/multipart/i.test(form.method)) return true;
  return form.fields.some((f) => /(file|upload|attachment|avatar|image|document)/i.test(f));
}

function collectAuthGatedUrls(evidence: ScanEvidence): Set<string> {
  const gated = new Set<string>();

  // Pages or role-probes that returned 401/403 are clearly protected.
  for (const page of evidence.pages) {
    if (page.status === 401 || page.status === 403) gated.add(normalizeUrl(page.url));
  }

  const roleProbes = evidence.roleProbes ?? {};
  const statusByUrl = new Map<string, Set<number>>();
  for (const results of Object.values(roleProbes)) {
    for (const r of results) {
      if (r.status === 401 || r.status === 403) gated.add(normalizeUrl(r.url));
      const key = normalizeUrl(r.url);
      const set = statusByUrl.get(key) ?? new Set<number>();
      set.add(r.status);
      statusByUrl.set(key, set);
    }
  }
  // If status varies across roles for the same URL, access is role-dependent.
  for (const [url, statuses] of statusByUrl) {
    if (statuses.size > 1) gated.add(url);
  }

  return gated;
}

function indexFormsByActionUrl(
  forms: DiscoveredForm[],
  targetUrl: string,
): Map<string, DiscoveredForm> {
  const map = new Map<string, DiscoveredForm>();
  for (const form of forms) {
    const action = form.action || form.pageUrl;
    const abs = absolutize(action, form.pageUrl || targetUrl);
    map.set(normalizeUrl(abs), form);
  }
  return map;
}

function absolutize(url: string, base: string): string {
  try {
    return new URL(url, base).toString();
  } catch {
    return url;
  }
}

function normalizeUrl(url: string): string {
  try {
    const u = new URL(url, 'http://placeholder.local');
    return `${u.origin}${u.pathname}`.replace(/\/$/, '');
  } catch {
    return (url.split('?')[0] ?? url).replace(/\/$/, '');
  }
}

function safePath(url: string): string {
  try {
    return new URL(url, 'http://placeholder.local').pathname;
  } catch {
    return url;
  }
}
