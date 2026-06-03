import { AuditLogger } from '../logging/audit-logger.js';
import { fieldsFromValidationError } from './auto-register.js';
import {
  sendRequest,
  type SendRequestResult,
  type Transport,
} from './http-request.js';
import type { AuthSession, TestAccount } from '../../types/scan.types.js';

/**
 * API payload finder.
 *
 * Given an API endpoint that rejects empty/malformed requests, this module
 * works out the *exact request shape it expects* by trying a short, bounded
 * sequence of steps and learning from each error response:
 *
 *   1. OPTIONS  → which methods does it allow?
 *   2. Bare POST {} → read the validation error; it usually names required fields.
 *   3. Fill discovered fields with typed placeholder values, re-send, and repeat
 *      until the server stops complaining (success) or no new fields surface.
 *   4. Fall back between JSON and form encodings.
 *
 * The output is a concrete payload the audit can then reuse to actually hit the
 * endpoint and run injection / auth / business-logic checks against it. All
 * requests are policy-checked and capped; payloads use benign placeholders.
 */
export interface PayloadFinderOptions {
  url: string;
  method?: string;
  account?: TestAccount;
  session?: AuthSession;
  extraAllowedHosts?: string[];
  audit: AuditLogger;
  transport?: Transport;
  /** Max learn-and-retry rounds (default 5). */
  maxRounds?: number;
}

export interface PayloadFinderStep {
  round: number;
  method: string;
  encoding: 'json' | 'form';
  sentFields: string[];
  status: number;
  newFieldsLearned: string[];
  note?: string;
}

export interface PayloadFinderResult {
  url: string;
  /** Methods advertised via OPTIONS Allow header, if any. */
  allowedMethods: string[];
  /** The method/encoding that made progress. */
  method: string;
  encoding: 'json' | 'form';
  /** Field names the server required, learned from its own errors. */
  requiredFields: string[];
  /** A concrete, benign payload that satisfied (or best-effort satisfied) it. */
  inferredPayload: Record<string, unknown>;
  /** Final status reached with the inferred payload. */
  finalStatus: number;
  /** True when a 2xx/201 was reached — the payload shape is confirmed. */
  succeeded: boolean;
  steps: PayloadFinderStep[];
}

const COMMON_SEED_FIELDS = ['email', 'name', 'username', 'title', 'id'];

export async function findApiPayload(opts: PayloadFinderOptions): Promise<PayloadFinderResult> {
  const transport = opts.transport ?? sendRequest;
  const maxRounds = opts.maxRounds ?? 5;
  const steps: PayloadFinderStep[] = [];

  // 1. OPTIONS — discover allowed methods.
  const allowedMethods = await discoverMethods(opts, transport);
  const method =
    opts.method ??
    pickWriteMethod(allowedMethods) ??
    'POST';

  // 2-3. Learn-and-retry across encodings.
  let best: PayloadFinderResult | null = null;
  for (const encoding of ['json', 'form'] as const) {
    const known = new Map<string, unknown>();
    let succeeded = false;
    let finalStatus = 0;

    for (let round = 1; round <= maxRounds; round++) {
      const payload = Object.fromEntries(known);
      let res: SendRequestResult;
      try {
        res = await transport({
          url: opts.url,
          method,
          headers: { 'content-type': encoding === 'json' ? 'application/json' : 'application/x-www-form-urlencoded' },
          body: encode(encoding, payload),
          account: opts.account,
          session: opts.session,
          extraAllowedHosts: opts.extraAllowedHosts,
        });
      } catch (err) {
        steps.push({
          round,
          method,
          encoding,
          sentFields: Object.keys(payload),
          status: 0,
          newFieldsLearned: [],
          note: err instanceof Error ? err.message : String(err),
        });
        break;
      }
      finalStatus = res.status;

      const learned = fieldsFromValidationError(res.body).filter((f) => !known.has(f));
      steps.push({
        round,
        method,
        encoding,
        sentFields: Object.keys(payload),
        status: res.status,
        newFieldsLearned: learned,
      });

      if (res.status >= 200 && res.status < 300) {
        succeeded = true;
        break;
      }

      // Seed common fields on the first round if the error gave us nothing.
      const toAdd = learned.length > 0 ? learned : round === 1 ? seedFields(opts.url, known) : [];
      if (toAdd.length === 0) break; // no progress possible
      for (const f of toAdd) known.set(f, placeholderFor(f));
    }

    const candidate: PayloadFinderResult = {
      url: opts.url,
      allowedMethods,
      method,
      encoding,
      requiredFields: [...known.keys()],
      inferredPayload: Object.fromEntries(known),
      finalStatus,
      succeeded,
      steps: steps.filter((s) => s.encoding === encoding),
    };
    if (!best || rank(candidate) > rank(best)) best = candidate;
    if (succeeded) break; // good enough
  }

  opts.audit.event('payload-finder.done', {
    url: opts.url,
    succeeded: best?.succeeded ?? false,
    fields: best?.requiredFields.length ?? 0,
  });
  // best is always set (loop runs at least once).
  return { ...best!, steps };
}

async function discoverMethods(
  opts: PayloadFinderOptions,
  transport: Transport,
): Promise<string[]> {
  try {
    const res = await transport({
      url: opts.url,
      method: 'OPTIONS',
      account: opts.account,
      session: opts.session,
      extraAllowedHosts: opts.extraAllowedHosts,
    });
    const allow = res.headers['allow'] ?? res.headers['access-control-allow-methods'];
    if (!allow) return [];
    return allow
      .split(',')
      .map((m) => m.trim().toUpperCase())
      .filter(Boolean);
  } catch {
    return [];
  }
}

function pickWriteMethod(methods: string[]): string | undefined {
  for (const m of ['POST', 'PUT', 'PATCH']) if (methods.includes(m)) return m;
  return undefined;
}

/** Guess likely field names from the URL when the server gives no hints. */
export function seedFields(url: string, known: Map<string, unknown>): string[] {
  const path = safePath(url).toLowerCase();
  const guesses = new Set<string>();
  if (/login|signin|auth/.test(path)) {
    guesses.add('email');
    guesses.add('password');
  }
  if (/user|account|register|signup/.test(path)) {
    guesses.add('email');
    guesses.add('password');
    guesses.add('name');
  }
  if (/order|cart|checkout/.test(path)) {
    guesses.add('quantity');
    guesses.add('productId');
  }
  if (/comment|post|message/.test(path)) {
    guesses.add('content');
  }
  for (const f of COMMON_SEED_FIELDS) guesses.add(f);
  return [...guesses].filter((f) => !known.has(f)).slice(0, 4);
}

/** Pick a benign, type-appropriate placeholder value for a field name. */
export function placeholderFor(field: string): unknown {
  const f = field.toLowerCase();
  if (/e-?mail/.test(f)) return 'smcp@smcp-test.invalid';
  if (/pass(word|wd)?/.test(f)) return 'Smcp!test1A';
  if (/(qty|quantity|count|amount|num|age)/.test(f)) return 1;
  if (/(price|total|cost)/.test(f)) return 1;
  if (/(is_|^is[A-Z]|enabled|active|flag)/.test(field)) return true;
  if (/(id|_id)$/.test(f)) return '1';
  if (/(date|time|_at)$/.test(f)) return '2026-01-01';
  if (/(url|link|website)/.test(f)) return 'http://localhost/';
  return 'smcp_test';
}

function encode(encoding: 'json' | 'form', payload: Record<string, unknown>): string {
  if (encoding === 'json') return JSON.stringify(payload);
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(payload)) {
    params.set(k, Array.isArray(v) ? v.join(',') : String(v));
  }
  return params.toString();
}

/** Score a candidate: success beats progress beats nothing. */
function rank(r: PayloadFinderResult): number {
  if (r.succeeded) return 1000 + r.requiredFields.length;
  return r.requiredFields.length;
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}
