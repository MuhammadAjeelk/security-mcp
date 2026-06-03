import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchPage } from './http-scanner.js';
import { getEnv } from '../../config/env.js';
import type { AuthSession, DiscoveredEndpoint, TestAccount } from '../../types/scan.types.js';
import { AuditLogger } from '../logging/audit-logger.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_WORDLIST = resolve(__dirname, '../../../wordlists/common-paths.txt');

/**
 * Wordlist-based content discovery. Brute-forces a small, curated list of
 * high-signal paths (admin panels, backups, config/secret files, API roots)
 * that the link crawl would never reach because nothing links to them. Every
 * request is a safe GET; only responses that look "present" (not 404/410 and
 * not an obvious soft-404) are recorded as endpoints.
 *
 * Hard-bounded by `SCAN_WORDLIST_MAX` and the shared crawl budget so it can
 * never generate abusive load.
 */
export interface ContentDiscoveryOptions {
  rootUrl: string;
  account?: TestAccount;
  session?: AuthSession;
  extraAllowedHosts?: string[];
  audit: AuditLogger;
  /** Hard cap on requests this routine may issue (shares the crawl budget). */
  maxRequests: number;
  /** Override the wordlist path (tests). */
  wordlistPath?: string;
  /** Provide words directly instead of reading a file (tests). */
  words?: string[];
  /** Skip recording a path if its body length matches the soft-404 baseline. */
  notFoundBaseline?: { status: number; length: number };
}

export interface ContentDiscoveryResult {
  endpoints: DiscoveredEndpoint[];
  notes: string[];
  requestCount: number;
}

export async function discoverContent(
  opts: ContentDiscoveryOptions,
): Promise<ContentDiscoveryResult> {
  const env = getEnv();
  const origin = new URL(opts.rootUrl).origin;
  const words = opts.words ?? (await loadWordlist(opts.wordlistPath ?? DEFAULT_WORDLIST));
  const budget = Math.min(opts.maxRequests, env.SCAN_WORDLIST_MAX, words.length);

  const endpoints: DiscoveredEndpoint[] = [];
  const notes: string[] = [];
  let requestCount = 0;

  opts.audit.event('content-discovery.start', { candidates: budget });

  for (const word of words) {
    if (requestCount >= budget) {
      if (words.length > budget) {
        notes.push(
          `Content discovery covered ${requestCount}/${words.length} candidates (budget cap).`,
        );
      }
      break;
    }
    const url = origin + normalizePath(word);
    let res;
    try {
      res = await fetchPage({
        url,
        depth: 0,
        extraAllowedHosts: opts.extraAllowedHosts,
        account: opts.account,
        session: opts.session,
        audit: opts.audit,
      });
    } catch (err) {
      opts.audit.event('content-discovery.skip', {
        url,
        reason: err instanceof Error ? err.message : String(err),
      });
      continue;
    }
    requestCount += 1;

    if (isPresent(res.page.status, res.body.length, opts.notFoundBaseline)) {
      endpoints.push({ url, method: 'GET', source: 'content-discovery' });
    }
  }

  opts.audit.event('content-discovery.done', {
    requested: requestCount,
    found: endpoints.length,
  });
  return { endpoints, notes, requestCount };
}

/**
 * Decide whether a response indicates the path actually exists. We treat
 * anything that is not 404/410 and not an obvious soft-404 (same status and
 * body length as the baseline) as "present" — including 401/403, which are
 * themselves interesting (a protected resource is still attack surface).
 */
export function isPresent(
  status: number,
  bodyLength: number,
  baseline?: { status: number; length: number },
): boolean {
  if (status === 404 || status === 410) return false;
  if (status >= 500) return true; // server error on a guessed path is itself a signal
  if (baseline && status === baseline.status && bodyLength === baseline.length) {
    return false; // soft-404: indistinguishable from the not-found baseline
  }
  return status < 400 || status === 401 || status === 403;
}

export async function loadWordlist(path: string): Promise<string[]> {
  try {
    const raw = await readFile(path, 'utf8');
    return parseWordlist(raw);
  } catch {
    return [];
  }
}

export function parseWordlist(raw: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    if (seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }
  return out;
}

function normalizePath(word: string): string {
  return word.startsWith('/') ? word : '/' + word;
}
