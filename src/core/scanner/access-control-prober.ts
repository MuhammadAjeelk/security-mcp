import { AuditLogger } from '../logging/audit-logger.js';
import { sendRequest, type Transport } from './http-request.js';
import type { Finding } from '../../types/finding.types.js';
import type { AttackSurfaceEndpoint, TestAccount } from '../../types/scan.types.js';

/**
 * Broken Function Level Authorization (BFLA / OWASP API5) prober.
 *
 * Replays the exact techniques attackers use against admin/privileged routes —
 * but READ-ONLY and non-destructively:
 *
 *   1. Hit each admin-like / auth-gated endpoint UNAUTHENTICATED. A 2xx where
 *      auth should be required is a critical access-control break.
 *   2. Retry with the auth-bypass HEADER tricks attackers spray (spoofed
 *      client IP, X-Original-URL routing confusion, role-ish headers). If any
 *      flips a 401/403 into a 2xx, the gate is bypassable.
 *   3. If low-privilege test accounts are supplied, request the SAME admin
 *      endpoint as each role and compare: a non-admin principal receiving 2xx
 *      on an admin function is BFLA.
 *
 * Only safe methods are probed (GET/HEAD/OPTIONS). State-changing admin verbs
 * (POST/PATCH/PUT/DELETE) are NEVER invoked here — escalation against those is
 * reasoned about by the LLM using these signals, not executed.
 */
export interface AccessControlProbeOptions {
  endpoints: AttackSurfaceEndpoint[];
  accounts?: TestAccount[];
  extraAllowedHosts?: string[];
  audit: AuditLogger;
  transport?: Transport;
  /** Cap on admin endpoints probed (default 12). */
  maxEndpoints?: number;
}

/** Header tricks attackers use to bypass auth/IP gates on internal routes. */
export const BYPASS_HEADERS: Array<{ label: string; headers: Record<string, string> }> = [
  { label: 'X-Forwarded-For=127.0.0.1', headers: { 'x-forwarded-for': '127.0.0.1' } },
  { label: 'X-Real-IP=127.0.0.1', headers: { 'x-real-ip': '127.0.0.1' } },
  { label: 'X-Originating-IP=127.0.0.1', headers: { 'x-originating-ip': '127.0.0.1' } },
  { label: 'X-Custom-IP-Authorization=127.0.0.1', headers: { 'x-custom-ip-authorization': '127.0.0.1' } },
  { label: 'X-Forwarded-Host=localhost', headers: { 'x-forwarded-host': 'localhost' } },
  { label: 'X-Original-URL routing', headers: { 'x-original-url': '/' } },
  { label: 'X-Rewrite-URL routing', headers: { 'x-rewrite-url': '/' } },
  { label: 'Role=admin', headers: { role: 'admin' } },
  { label: 'X-Role=admin', headers: { 'x-role': 'admin' } },
  { label: 'X-Admin=true', headers: { 'x-admin': 'true' } },
  { label: 'X-User-Role=admin', headers: { 'x-user-role': 'admin' } },
];

const SAFE = /^(GET|HEAD|OPTIONS)$/i;

export async function probeAccessControl(opts: AccessControlProbeOptions): Promise<Finding[]> {
  const transport = opts.transport ?? sendRequest;
  const max = opts.maxEndpoints ?? 12;
  const findings: Finding[] = [];

  // Target admin-like or auth-gated endpoints reachable with a SAFE method.
  const targets = opts.endpoints
    .filter((e) => (e.looksAdmin || e.authGated) && safeMethodFor(e))
    .slice(0, max);

  if (targets.length === 0) return findings;
  opts.audit.event('bfla.start', { targets: targets.length });

  for (const ep of targets) {
    const url = concreteUrl(ep.url);
    const method = SAFE.test(ep.method) ? ep.method.toUpperCase() : 'GET';

    // 1. Unauthenticated baseline.
    const baseline = await probe(transport, url, method, {}, opts);
    if (baseline === null) continue;

    if (isAuthorized(baseline.status)) {
      findings.push(
        finding(
          `Unauthenticated access to privileged route`,
          'critical',
          url,
          method,
          { status: baseline.status, requiredAuth: false },
          `${method} ${url} returned ${baseline.status} with no credentials. Admin/privileged functionality must reject anonymous callers.`,
          'Anonymous attacker invokes admin functionality directly (BFLA / OWASP API5).',
        ),
      );
      continue; // already broken; header tricks are moot
    }

    if (!isGated(baseline.status)) continue; // not a 401/403 → not a meaningful gate to bypass

    // 2. Header-trick bypasses. Require BOTH a status flip to 2xx AND a body
    // that differs from the gated baseline — guards against soft-200 error
    // pages (per the OWASP/PortSwigger "diff the body, not just the status").
    for (const trick of BYPASS_HEADERS) {
      const res = await probe(transport, url, method, trick.headers, opts);
      if (res !== null && isAuthorized(res.status) && bodyDiffers(baseline.bodyLen, res.bodyLen)) {
        findings.push(
          finding(
            `Auth gate bypassed via request header`,
            'critical',
            url,
            method,
            { baseline: baseline.status, bypassStatus: res.status, via: trick.label },
            `${method} ${url} returned ${baseline.status} normally but ${res.status} with a different body when sent with ${trick.label}. The gate trusts an attacker-controllable header.`,
            'Attacker bypasses authorization by spoofing a trusted header (proxy/IP/role confusion).',
          ),
        );
        break;
      }
    }

    // 3. Cross-role differential: a non-admin principal reaching an admin route.
    if (opts.accounts && opts.accounts.length > 0) {
      for (const acct of opts.accounts) {
        if (isAdminRole(acct.role)) continue; // only flag UNDER-privileged access
        const res = await probe(transport, url, method, {}, opts, acct);
        if (res !== null && isAuthorized(res.status) && ep.looksAdmin) {
          findings.push(
            finding(
              `Non-admin role can access admin route (BFLA)`,
              'high',
              url,
              method,
              { role: acct.role, status: res.status },
              `Role "${acct.role}" received ${res.status} on admin route ${method} ${url}. Function-level authorization is missing or role checks are not enforced.`,
              `Low-privilege user "${acct.role}" invokes admin functions → privilege escalation.`,
            ),
          );
          break;
        }
      }
    }
  }

  opts.audit.event('bfla.done', { findings: findings.length });
  return findings;
}

// --- helpers ---------------------------------------------------------------

async function probe(
  transport: Transport,
  url: string,
  method: string,
  headers: Record<string, string>,
  opts: AccessControlProbeOptions,
  account?: TestAccount,
): Promise<{ status: number; bodyLen: number } | null> {
  try {
    const res = await transport({
      url,
      method,
      headers,
      account,
      extraAllowedHosts: opts.extraAllowedHosts,
    });
    return { status: res.status, bodyLen: res.body.length };
  } catch (err) {
    opts.audit.event('bfla.error', {
      url,
      reason: err instanceof Error ? err.message : String(err),
    });
    return null;
  }
}

/**
 * A bypass is only credible if the now-allowed response returns materially
 * different content from the denied baseline (catches soft-200 error pages
 * that are the same size as the 401/403 body).
 */
export function bodyDiffers(gatedLen: number, allowedLen: number): boolean {
  if (allowedLen === 0) return false;
  return Math.abs(allowedLen - gatedLen) > 16;
}

/** 2xx (and non-empty 3xx to app content) means the call was honored. */
export function isAuthorized(status: number): boolean {
  return status >= 200 && status < 300;
}

export function isGated(status: number): boolean {
  return status === 401 || status === 403;
}

export function isAdminRole(role: string): boolean {
  return /admin|super|root|owner|staff/i.test(role);
}

function safeMethodFor(e: AttackSurfaceEndpoint): boolean {
  // We probe with GET regardless, but only target endpoints whose declared
  // method is safe OR that look like a readable resource — never to trigger a
  // declared state-changing operation.
  return SAFE.test(e.method) || e.method.toUpperCase() === 'GET';
}

/** Replace OpenAPI `{id}` template params with a concrete benign value. */
function concreteUrl(url: string): string {
  return url.replace(/\{[^/}]+\}|%7b[^/]*%7d/gi, '1');
}

function finding(
  title: string,
  severity: Finding['severity'],
  url: string,
  method: string,
  evidence: Record<string, unknown>,
  description: string,
  attackChain: string,
): Finding {
  return {
    id: `bfla.${shortHash(method + url + title)}`,
    title,
    severity,
    category: 'access-control',
    description,
    evidence: { url, method, ...evidence },
    impact: 'Unauthorized access to privileged/admin functionality.',
    remediation:
      'Enforce function-level authorization server-side on every privileged route (deny-by-default). ' +
      'Never trust client-supplied headers (X-Forwarded-*, role headers) for authz. Check the ' +
      "authenticated principal's role/permissions on each request.",
    confidence: 'high',
    promptId: 'access-control.bfla',
    attackChain,
  };
}

function shortHash(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
}
