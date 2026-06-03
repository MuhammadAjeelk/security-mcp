import { request } from 'undici';
import { validateTarget } from '../policy/target-policy.js';
import { getEnv } from '../../config/env.js';
import type { AuthSession, TestAccount } from '../../types/scan.types.js';

/**
 * Generic, policy-checked HTTP helper for the active modules that need to send
 * bodied requests (self-registration, API payload discovery). `http-scanner.ts`
 * is GET-only and crawl-oriented; this is the write-capable counterpart.
 *
 * Every call re-validates the target against the allowlist, so even bodied
 * requests can never escape the localhost/staging policy. State-changing
 * requests are the caller's responsibility to keep within the rules of
 * engagement (own-account actions, non-destructive payloads).
 */
export interface SendRequestInput {
  url: string;
  method: string;
  /** Header map (lowercased on the way out). */
  headers?: Record<string, string>;
  /** Raw body string (already serialized by the caller). */
  body?: string;
  account?: TestAccount;
  session?: AuthSession;
  extraAllowedHosts?: string[];
  /** Override timeout (defaults to SCAN_TIMEOUT_MS). */
  timeoutMs?: number;
}

export interface SendRequestResult {
  status: number;
  headers: Record<string, string>;
  body: string;
  setCookies: string[];
  durationMs: number;
}

/** Injectable transport so callers/tests can stub the network. */
export type Transport = (input: SendRequestInput) => Promise<SendRequestResult>;

const MAX_BODY_BYTES = 256 * 1024;

export async function sendRequest(input: SendRequestInput): Promise<SendRequestResult> {
  const env = getEnv();
  const decision = validateTarget(input.url, { extraAllowedHosts: input.extraAllowedHosts });
  if (!decision.allowed) {
    throw new Error(`Refusing to request ${input.url}: ${decision.reason}`);
  }

  const headers: Record<string, string> = {
    'user-agent': 'security-mcp/0.4 (+authorized-testing-only)',
    accept: 'application/json, text/html;q=0.9, */*;q=0.5',
    ...lower(input.headers),
  };
  if (input.account?.token) headers['authorization'] = `Bearer ${input.account.token}`;
  else if (input.session?.bearerToken) headers['authorization'] = `Bearer ${input.session.bearerToken}`;
  const cookies = { ...(input.session?.cookies ?? {}), ...(input.account?.cookies ?? {}) };
  if (Object.keys(cookies).length > 0) {
    headers['cookie'] = Object.entries(cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), input.timeoutMs ?? env.SCAN_TIMEOUT_MS);
  const start = Date.now();
  try {
    const response = await request(input.url, {
      method: input.method.toUpperCase() as never,
      headers,
      body: input.body,
      signal: controller.signal,
      maxRedirections: 0,
    });
    const flat: Record<string, string> = {};
    for (const [k, v] of Object.entries(response.headers)) {
      if (v === undefined) continue;
      flat[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
    }
    const setCookieRaw = response.headers['set-cookie'];
    const setCookies = Array.isArray(setCookieRaw)
      ? setCookieRaw
      : setCookieRaw
        ? [String(setCookieRaw)]
        : [];
    const text = (await response.body.text()).slice(0, MAX_BODY_BYTES);
    return {
      status: response.statusCode,
      headers: flat,
      body: text,
      setCookies,
      durationMs: Date.now() - start,
    };
  } finally {
    clearTimeout(timer);
  }
}

function lower(headers?: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers ?? {})) out[k.toLowerCase()] = v;
  return out;
}

/** Parse a Set-Cookie header list into a name→value cookie map. */
export function cookiesFromSetCookie(setCookies: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of setCookies) {
    const first = raw.split(';')[0] ?? '';
    const eq = first.indexOf('=');
    if (eq <= 0) continue;
    const name = first.slice(0, eq).trim();
    const value = first.slice(eq + 1).trim();
    if (name) out[name] = value;
  }
  return out;
}
