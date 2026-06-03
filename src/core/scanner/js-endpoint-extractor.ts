import { fetchPage } from './http-scanner.js';
import { getEnv } from '../../config/env.js';
import type {
  AuthSession,
  DiscoveredEndpoint,
  ScannedPage,
  TestAccount,
} from '../../types/scan.types.js';
import { AuditLogger } from '../logging/audit-logger.js';

/**
 * Modern SPAs declare their API surface inside bundled JavaScript, not in HTML
 * links. This module downloads the same-origin `.js` assets referenced by the
 * crawled pages and regexes out the API paths / fetch-axios call targets /
 * route literals embedded in them. Read-only and bounded by `SCAN_JS_BUNDLE_MAX`.
 */
export interface JsExtractOptions {
  rootUrl: string;
  /** Pages already crawled — their HTML bodies are scanned for <script src>. */
  pages: ScannedPage[];
  /** HTML bodies keyed by finalUrl (the crawler holds these transiently). */
  htmlByUrl: Record<string, string>;
  account?: TestAccount;
  session?: AuthSession;
  extraAllowedHosts?: string[];
  audit: AuditLogger;
  maxRequests: number;
}

export interface JsExtractResult {
  endpoints: DiscoveredEndpoint[];
  notes: string[];
  requestCount: number;
}

const SCRIPT_SRC_RE = /<script\b[^>]*?\bsrc\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']/gi;

export async function extractJsEndpoints(opts: JsExtractOptions): Promise<JsExtractResult> {
  const env = getEnv();
  const origin = new URL(opts.rootUrl).origin;
  const budget = Math.min(opts.maxRequests, env.SCAN_JS_BUNDLE_MAX);

  const scriptUrls = collectScriptUrls(opts.htmlByUrl, origin);
  const endpoints: DiscoveredEndpoint[] = [];
  const notes: string[] = [];
  let requestCount = 0;

  for (const scriptUrl of scriptUrls) {
    if (requestCount >= budget) {
      if (scriptUrls.length > budget) {
        notes.push(`JS extraction covered ${requestCount}/${scriptUrls.length} bundles (cap).`);
      }
      break;
    }
    let res;
    try {
      res = await fetchPage({
        url: scriptUrl,
        depth: 0,
        extraAllowedHosts: opts.extraAllowedHosts,
        account: opts.account,
        session: opts.session,
        audit: opts.audit,
      });
    } catch (err) {
      opts.audit.event('js-extract.skip', {
        url: scriptUrl,
        reason: err instanceof Error ? err.message : String(err),
      });
      continue;
    }
    requestCount += 1;
    if (res.page.status < 200 || res.page.status >= 400) continue;

    for (const path of extractPathsFromJs(res.body)) {
      const abs = absolutize(path, origin);
      if (abs && new URL(abs).origin === origin) {
        endpoints.push({ url: abs, method: 'GET', source: 'js-bundle' });
      }
    }
  }

  const deduped = dedupe(endpoints);
  if (deduped.length > 0) {
    notes.push(`Extracted ${deduped.length} endpoint path(s) from JS bundles.`);
  }
  return { endpoints: deduped, notes, requestCount };
}

export function collectScriptUrls(
  htmlByUrl: Record<string, string>,
  origin: string,
): string[] {
  const urls = new Set<string>();
  for (const [pageUrl, html] of Object.entries(htmlByUrl)) {
    for (const m of html.matchAll(SCRIPT_SRC_RE)) {
      const abs = absolutize(m[1]!, pageUrl);
      if (abs && safeOrigin(abs) === origin) urls.add(abs);
    }
  }
  return [...urls];
}

// Quoted strings that look like API/route paths, plus explicit fetch/axios calls.
const PATH_LITERAL_RE = /["'`](\/(?:api|v\d+|graphql|rest|auth|users?|admin)[A-Za-z0-9_\-./{}:]*)["'`]/g;
const FETCH_CALL_RE = /\b(?:fetch|axios(?:\.\w+)?)\s*\(\s*["'`]([^"'`]+)["'`]/g;

/**
 * Pull candidate endpoint paths out of a JS bundle. Conservative on purpose —
 * only matches strings that begin with a recognizable API/route prefix or are
 * the first argument to a fetch/axios call, to avoid flooding the surface with
 * CSS classes and i18n keys.
 */
export function extractPathsFromJs(js: string): string[] {
  const out = new Set<string>();
  for (const m of js.matchAll(PATH_LITERAL_RE)) {
    out.add(stripQuery(m[1]!));
  }
  for (const m of js.matchAll(FETCH_CALL_RE)) {
    const raw = m[1]!;
    if (raw.startsWith('/') || /^https?:\/\//i.test(raw)) out.add(stripQuery(raw));
  }
  return [...out];
}

function stripQuery(p: string): string {
  const q = p.indexOf('?');
  return q >= 0 ? p.slice(0, q) : p;
}

function absolutize(value: string, base: string): string | null {
  try {
    return new URL(value, base).toString();
  } catch {
    return null;
  }
}

function safeOrigin(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
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
