import { sendRequest, type SendRequestResult } from './http-request.js';
import { validateTarget } from '../policy/target-policy.js';
import { getEnv } from '../../config/env.js';
import { AuditLogger } from '../logging/audit-logger.js';
import type { AuthSession, TestAccount } from '../../types/scan.types.js';

/**
 * Authorized brute-force engine for guessable secrets (verification / OTP / 2FA
 * codes, numeric reset PINs). It exists to *prove* a missing-rate-limit
 * vulnerability: if the target throttles, that is the secure outcome and the run
 * aborts; only an unthrottled endpoint gets the full keyspace.
 *
 * Hard safety rails (these are non-negotiable, not knobs):
 *  - every single request is re-checked against the target policy (localhost /
 *    *staging* only) — it can never escape scope mid-run;
 *  - it self-aborts the moment throttling appears (429/503/Retry-After or a
 *    sustained block), so it backs off instead of becoming a DoS;
 *  - attempts are capped by SCAN_BRUTE_MAX and run at bounded concurrency.
 */

export type BruteEncoding = 'json' | 'form' | 'query';

export interface BruteForceSpec {
  /** Endpoint that consumes the secret (e.g. POST /auth/verify-email). */
  url: string;
  method?: string;
  /** Field that carries the guessed secret. */
  codeParam: string;
  /** Numeric code length to sweep (e.g. 6 → 000000–999999). */
  codeLength: number;
  /** Other fields sent on every request (e.g. { email: "x@smcp-test.invalid" }). */
  staticFields?: Record<string, unknown>;
  encoding?: BruteEncoding;
  /** Status codes that mean "the guess was accepted". Default 200/201/204/302. */
  successStatuses?: number[];
  /** Optional success signal in the response body (regex source). */
  successBodyRegex?: string;
  account?: TestAccount;
  session?: AuthSession;
  extraAllowedHosts?: string[];
  audit: AuditLogger;
}

export interface BruteForceResult {
  /** Whether the rate-limit precheck found effective throttling. */
  rateLimited: boolean;
  /** The accepted secret, if cracked. */
  found?: string;
  attempts: number;
  aborted: boolean;
  abortReason?: string;
  /** Short human note for the report. */
  note: string;
}

const THROTTLE_STATUSES = new Set([429, 503]);
// Fraction of a recent window that must be throttled before we back off.
const THROTTLE_ABORT_RATIO = 0.3;

export async function bruteForceNumericCode(spec: BruteForceSpec): Promise<BruteForceResult> {
  const env = getEnv();
  const method = (spec.method ?? 'POST').toUpperCase();
  const successStatuses = new Set(spec.successStatuses ?? [200, 201, 204, 302]);
  const successRe = spec.successBodyRegex ? safeRegex(spec.successBodyRegex) : null;
  const space = Math.min(10 ** spec.codeLength, env.SCAN_BRUTE_MAX);

  // Scope check up front — never start against a non-allowlisted host.
  const decision = validateTarget(spec.url, { extraAllowedHosts: spec.extraAllowedHosts });
  if (!decision.allowed) {
    return {
      rateLimited: false,
      attempts: 0,
      aborted: true,
      abortReason: `target rejected by policy: ${decision.reason}`,
      note: 'Brute-force not started — target out of scope.',
    };
  }

  // 1) Rate-limit precheck: a quick burst of wrong guesses. If the server
  //    throttles, that is the SECURE outcome — stop and report it.
  const sample = Math.min(env.SCAN_RATELIMIT_SAMPLE, space);
  spec.audit.event('brute.precheck.start', { url: spec.url, sample });
  let throttledInSample = 0;
  for (let i = 0; i < sample; i++) {
    const code = pad(i, spec.codeLength);
    const res = await attempt(spec, method, code).catch(() => null);
    if (!res) continue;
    if (THROTTLE_STATUSES.has(res.status) || res.headers['retry-after']) throttledInSample++;
    if (isSuccess(res, successStatuses, successRe)) {
      // Cracked it inside the precheck window.
      return {
        rateLimited: false,
        found: code,
        attempts: i + 1,
        aborted: false,
        note: `Code accepted after ${i + 1} attempts — no rate limiting.`,
      };
    }
  }
  if (throttledInSample / sample >= THROTTLE_ABORT_RATIO) {
    spec.audit.event('brute.precheck.throttled', { url: spec.url, throttledInSample, sample });
    return {
      rateLimited: true,
      attempts: sample,
      aborted: true,
      abortReason: 'rate limiting detected in precheck',
      note: 'Rate limiting / throttling is active on this endpoint — brute-force aborted (secure).',
    };
  }

  // 2) No throttling → sweep the remaining keyspace at bounded concurrency,
  //    stopping on success and backing off if throttling appears mid-run.
  spec.audit.event('brute.sweep.start', { url: spec.url, space, concurrency: env.SCAN_BRUTE_CONCURRENCY });
  let next = sample;
  let attempts = sample;
  let found: string | undefined;
  let aborted = false;
  let abortReason: string | undefined;
  const recent: boolean[] = []; // sliding window of throttle flags

  async function worker(): Promise<void> {
    while (!found && !aborted) {
      const i = next++;
      if (i >= space) return;
      const code = pad(i, spec.codeLength);
      let res: SendRequestResult | null = null;
      try {
        res = await attempt(spec, method, code);
      } catch {
        res = null;
      }
      attempts++;
      if (!res) continue;

      const throttled = THROTTLE_STATUSES.has(res.status) || !!res.headers['retry-after'];
      recent.push(throttled);
      if (recent.length > 40) recent.shift();
      if (recent.length >= 20 && recent.filter(Boolean).length / recent.length >= THROTTLE_ABORT_RATIO) {
        aborted = true;
        abortReason = 'throttling appeared mid-run — backed off';
        return;
      }
      if (isSuccess(res, successStatuses, successRe)) {
        found = code;
        return;
      }
    }
  }

  const workers = Array.from({ length: env.SCAN_BRUTE_CONCURRENCY }, () => worker());
  await Promise.all(workers);

  if (found) {
    spec.audit.event('brute.sweep.cracked', { url: spec.url, attempts });
    return {
      rateLimited: false,
      found,
      attempts,
      aborted: false,
      note: `Secret cracked in ${attempts} attempts — endpoint has NO rate limiting.`,
    };
  }
  if (aborted) {
    spec.audit.event('brute.sweep.aborted', { url: spec.url, attempts, abortReason });
    return {
      rateLimited: abortReason?.includes('throttl') ?? false,
      attempts,
      aborted: true,
      abortReason,
      note: `Brute-force aborted after ${attempts} attempts: ${abortReason}.`,
    };
  }
  spec.audit.event('brute.sweep.exhausted', { url: spec.url, attempts });
  return {
    rateLimited: false,
    attempts,
    aborted: false,
    note:
      attempts >= space && space < 10 ** spec.codeLength
        ? `Exhausted SCAN_BRUTE_MAX (${space}) without success — no throttling seen; raise the cap to finish the keyspace.`
        : `Swept ${attempts} candidates without a hit; no throttling observed.`,
  };
}

async function attempt(
  spec: BruteForceSpec,
  method: string,
  code: string,
): Promise<SendRequestResult> {
  const fields = { ...(spec.staticFields ?? {}), [spec.codeParam]: code };
  const encoding = spec.encoding ?? 'json';
  if (encoding === 'query') {
    const u = new URL(spec.url);
    for (const [k, v] of Object.entries(fields)) u.searchParams.set(k, String(v));
    return sendRequest({
      url: u.toString(),
      method,
      account: spec.account,
      session: spec.session,
      extraAllowedHosts: spec.extraAllowedHosts,
    });
  }
  const isForm = encoding === 'form';
  const body = isForm
    ? new URLSearchParams(Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, String(v)]))).toString()
    : JSON.stringify(fields);
  return sendRequest({
    url: spec.url,
    method,
    headers: { 'content-type': isForm ? 'application/x-www-form-urlencoded' : 'application/json' },
    body,
    account: spec.account,
    session: spec.session,
    extraAllowedHosts: spec.extraAllowedHosts,
  });
}

function isSuccess(res: SendRequestResult, statuses: Set<number>, re: RegExp | null): boolean {
  if (re && re.test(res.body)) return true;
  // A success status that is NOT also a generic throttle/error.
  return statuses.has(res.status) && !THROTTLE_STATUSES.has(res.status);
}

function pad(n: number, len: number): string {
  return n.toString().padStart(len, '0');
}

function safeRegex(src: string): RegExp | null {
  try {
    return new RegExp(src, 'i');
  } catch {
    return null;
  }
}
