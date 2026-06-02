import { request } from 'undici';
import { evaluateRedirect } from '../policy/redirect-policy.js';
import { validateTarget } from '../policy/target-policy.js';
import { getEnv } from '../../config/env.js';
import type { ScannedPage, TestAccount } from '../../types/scan.types.js';
import { AuditLogger } from '../logging/audit-logger.js';

export interface HttpScanOptions {
  url: string;
  depth: number;
  maxRedirects?: number;
  extraAllowedHosts?: string[];
  account?: TestAccount;
  session?: import('../../types/scan.types.js').AuthSession;
  audit: AuditLogger;
}

export interface HttpScanResult {
  page: ScannedPage;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  truncated: boolean;
}

const MAX_BODY_BYTES = 256 * 1024;
const DEFAULT_MAX_REDIRECTS = 3;

export async function fetchPage(opts: HttpScanOptions): Promise<HttpScanResult> {
  const env = getEnv();
  const maxRedirects = opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS;

  let currentUrl = opts.url;
  let redirected = false;
  let hops = 0;

  while (true) {
    const initial = validateTarget(currentUrl, { extraAllowedHosts: opts.extraAllowedHosts });
    if (!initial.allowed) {
      throw new Error(`Refusing to fetch ${currentUrl}: ${initial.reason}`);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), env.SCAN_TIMEOUT_MS);

    opts.audit.event('http.request', { url: currentUrl, depth: opts.depth });

    try {
      const response = await request(currentUrl, {
        method: 'GET',
        headers: buildHeaders(opts.account, opts.session),
        signal: controller.signal,
        maxRedirections: 0,
      });

      const status = response.statusCode;
      const headersFlat = flattenHeaders(response.headers);
      const setCookieRaw = response.headers['set-cookie'];
      const setCookies = Array.isArray(setCookieRaw)
        ? setCookieRaw
        : setCookieRaw
          ? [String(setCookieRaw)]
          : [];

      if (status >= 300 && status < 400 && headersFlat['location']) {
        if (hops >= maxRedirects) {
          opts.audit.event('http.redirect.stop', {
            from: currentUrl,
            reason: 'max-redirects-exceeded',
          });
          break;
        }
        const decision = evaluateRedirect(
          currentUrl,
          headersFlat['location']!,
          opts.extraAllowedHosts,
        );
        if (!decision.follow) {
          opts.audit.event('http.redirect.blocked', {
            from: currentUrl,
            location: headersFlat['location'],
            reason: decision.reason,
          });
          await response.body.dump();
          return {
            page: {
              url: opts.url,
              status,
              contentType: headersFlat['content-type'],
              bytes: 0,
              redirected: true,
              finalUrl: currentUrl,
              depth: opts.depth,
            },
            headers: headersFlat,
            setCookies,
            body: '',
            truncated: false,
          };
        }
        await response.body.dump();
        currentUrl = new URL(headersFlat['location']!, currentUrl).toString();
        hops += 1;
        redirected = true;
        continue;
      }

      const { body, truncated } = await readBoundedBody(response.body);
      return {
        page: {
          url: opts.url,
          status,
          contentType: headersFlat['content-type'],
          bytes: body.length,
          redirected,
          finalUrl: currentUrl,
          depth: opts.depth,
        },
        headers: headersFlat,
        setCookies,
        body,
        truncated,
      };
    } finally {
      clearTimeout(timer);
    }
  }

  throw new Error(`Unable to fetch ${opts.url} within redirect budget`);
}

function buildHeaders(account?: TestAccount, session?: import('../../types/scan.types.js').AuthSession): Record<string, string> {
  const headers: Record<string, string> = {
    'user-agent': 'security-mcp/0.2 (+authorized-testing-only)',
    accept: 'text/html,application/json;q=0.9,*/*;q=0.5',
  };
  // Account takes precedence, then a recorded session.
  if (account?.token) {
    headers['authorization'] = `Bearer ${account.token}`;
  } else if (session?.bearerToken) {
    headers['authorization'] = `Bearer ${session.bearerToken}`;
  }
  const cookies: Record<string, string> = {
    ...(session?.cookies ?? {}),
    ...(account?.cookies ?? {}),
  };
  if (Object.keys(cookies).length > 0) {
    headers['cookie'] = Object.entries(cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }
  return headers;
}

function flattenHeaders(raw: Record<string, string | string[] | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (v === undefined) continue;
    out[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  return out;
}

async function readBoundedBody(
  body: NodeJS.ReadableStream,
): Promise<{ body: string; truncated: boolean }> {
  const chunks: Buffer[] = [];
  let total = 0;
  let truncated = false;
  for await (const chunk of body) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (total + buf.length > MAX_BODY_BYTES) {
      const remaining = MAX_BODY_BYTES - total;
      if (remaining > 0) chunks.push(buf.subarray(0, remaining));
      total = MAX_BODY_BYTES;
      truncated = true;
      break;
    }
    chunks.push(buf);
    total += buf.length;
  }
  return { body: Buffer.concat(chunks).toString('utf8'), truncated };
}
