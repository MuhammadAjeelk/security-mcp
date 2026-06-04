import { AuditLogger } from '../logging/audit-logger.js';
import { sendRequest, type Transport } from './http-request.js';
import type { Finding } from '../../types/finding.types.js';
import type { AttackSurfaceEndpoint, AuthSession, TestAccount } from '../../types/scan.types.js';

/**
 * Post-authentication role escalation via PROFILE UPDATE (mass assignment).
 *
 * The classic, still-shipping bug: an app validates `role` at REGISTRATION but
 * binds the profile/account update straight to the user model, so a normal user
 * can PATCH their own `role` to admin. The registration probe and the BFLA
 * prober don't catch this (the latter never sends state-changing verbs), so
 * this module does it directly — but ONLY against the authenticated account the
 * caller supplied (own account, never another user).
 *
 * Method: read the current profile → send an update that includes privilege
 * fields the form never advertised → re-read the profile and check whether any
 * privilege field actually changed toward "elevated". Verdict requires the
 * change to PERSIST on read-back (a bare 2xx is not proof).
 */

const UPDATE_PATH_RE = /\/(me|profile|account|users?|settings|account\/preferences)(\/|$)/i;

/** Boolean / permission flags sent on every attempt. */
const ESCALATION_FLAGS: Record<string, unknown> = {
  isAdmin: true,
  is_admin: true,
  admin: true,
  isStaff: true,
  isSuperuser: true,
  is_superuser: true,
  permissions: ['*'],
  groups: ['administrators'],
};

/**
 * Candidate higher-privilege role VALUES. Escalation is domain-specific — it is
 * not always "admin": EdTech is student→teacher, marketplaces are member→owner,
 * CMS is viewer→editor. The bug is that the user can set their own role to ANY
 * of these at all, so we try the common privileged values across a few attempts.
 */
const ROLE_CANDIDATES: readonly string[] = Object.freeze([
  'admin', 'administrator', 'superadmin', 'superuser', 'owner', 'teacher', 'instructor',
  'manager', 'editor', 'moderator', 'supervisor', 'staff', 'organizer', 'lead',
]);

/** Build a bounded list of update payloads, each trying one candidate role value. */
function buildPayloads(maxAttempts: number): Array<{ payload: Record<string, unknown>; roleValue: string }> {
  return ROLE_CANDIDATES.slice(0, maxAttempts).map((roleValue) => ({
    roleValue,
    payload: {
      ...ESCALATION_FLAGS,
      role: roleValue,
      roles: [roleValue],
      accountType: roleValue,
      type: roleValue,
      tier: roleValue,
      organizationRole: roleValue === 'owner' ? 'owner' : roleValue,
    },
  }));
}

const ROLE_KEYS = [
  'role', 'roles', 'isadmin', 'is_admin', 'admin', 'isstaff', 'issuperuser', 'is_superuser',
  'permissions', 'groups', 'accounttype', 'tier', 'type', 'organizationrole',
];

export interface ProfileEscalationOptions {
  endpoints: AttackSurfaceEndpoint[];
  account?: TestAccount;
  session?: AuthSession;
  extraAllowedHosts?: string[];
  audit: AuditLogger;
  transport?: Transport;
  /** Cap on update endpoints probed (default 6). */
  maxEndpoints?: number;
  /** Candidate role values tried per endpoint (default 4). */
  maxAttempts?: number;
}

export async function probeProfileEscalation(opts: ProfileEscalationOptions): Promise<Finding[]> {
  // Strictly a post-auth test: needs a credential, else there is no "self".
  const authed = !!(opts.account?.token || opts.account?.cookies || opts.session?.bearerToken || opts.session?.cookies);
  if (!authed) return [];

  const transport = opts.transport ?? sendRequest;
  const max = opts.maxEndpoints ?? 6;
  const findings: Finding[] = [];

  // Candidate self-mutating endpoints (own profile/account/settings).
  const updateTargets = opts.endpoints
    .filter((e) => /^(PUT|PATCH|POST)$/i.test(e.method) && UPDATE_PATH_RE.test(safePath(e.url)))
    .slice(0, max);
  if (updateTargets.length === 0) return findings;

  const attemptsPerEndpoint = Math.max(1, Math.min(opts.maxAttempts ?? 4, ROLE_CANDIDATES.length));
  opts.audit.event('profile-escalation.start', { targets: updateTargets.length, attemptsPerEndpoint });

  // Find a self-read endpoint to confirm persistence.
  const readUrl = pickSelfReadUrl(opts.endpoints);
  const baseline = readUrl ? await readSignals(transport, readUrl, opts) : null;

  for (const ep of updateTargets) {
    const url = concrete(ep.url);
    const method = ep.method.toUpperCase();
    let reported = false;
    let softReported = false;

    for (const { payload, roleValue } of buildPayloads(attemptsPerEndpoint)) {
      if (reported) break;
      let res;
      try {
        res = await transport({
          url,
          method,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
          account: opts.account,
          session: opts.session,
          extraAllowedHosts: opts.extraAllowedHosts,
        });
      } catch (err) {
        opts.audit.event('profile-escalation.error', { url, reason: err instanceof Error ? err.message : String(err) });
        continue;
      }

      const after = readUrl ? await readSignals(transport, readUrl, opts) : signalsFromBody(res.body);
      const verdict = detectElevation(baseline, after, res.body, payload);

      if (verdict.vulnerable) {
        reported = true;
        findings.push({
          id: `profile-escalation.${shortId(url)}`,
          title: 'Privilege escalation via profile/account update (mass assignment)',
          severity: 'critical',
          category: 'access-control',
          description:
            `${method} ${url} let a normal user set their own privileged field on a self-update and the ` +
            `change PERSISTED on read-back (${verdict.detail}). The user controls their own role — ` +
            `escalation need not be to "admin"; any higher role in the app's hierarchy (e.g. ` +
            `student→teacher, member→owner) is a full break.`,
          evidence: { url, method, injectedRole: roleValue, persisted: verdict.detail, status: res.status },
          impact: 'Any logged-in user can elevate their own role → privilege escalation and likely admin-panel takeover.',
          remediation:
            'Allowlist updatable fields server-side (DTO whitelist / strong params); never bind the ' +
            'request body to privileged attributes (role, roles, is_admin, permissions, accountType). ' +
            'Role changes must go through a separate, authorized admin path. Add a regression test that ' +
            'sends role=<higher> as a normal user on profile update and asserts it is ignored.',
          confidence: 'high',
          promptId: 'access-control.role-escalation',
          attackChain:
            `Register/login as a normal user → ${method} ${url} with role=${roleValue} → server ` +
            `mass-assigns it → re-read profile shows the elevated role → reach role-gated/admin routes.`,
        });
      } else if (verdict.softHit && !softReported) {
        softReported = true;
        findings.push({
          id: `profile-escalation.soft.${shortId(url)}`,
          title: 'Profile update accepted a privileged role field (2xx) — verify persistence',
          severity: 'medium',
          category: 'access-control',
          description:
            `${method} ${url} returned ${res.status} and echoed an injected role value (role=${roleValue}), ` +
            `but persistence on an independent read-back could not be confirmed. Manually verify whether ` +
            `the role actually changed.`,
          evidence: { url, method, status: res.status, injectedRole: roleValue },
          impact: 'Potential privilege escalation if the role field is bound to the user model.',
          remediation: 'Allowlist updatable fields; confirm the server ignores client-supplied role on self-update.',
          confidence: 'low',
          promptId: 'access-control.role-escalation',
        });
      }
    }
    opts.audit.event('profile-escalation.done', { url, vulnerable: reported });
  }

  return findings;
}

interface Signals {
  values: Record<string, string>;
}

/**
 * Vulnerable when, on independent read-back, a role-ish field changed to a value
 * WE injected (proves the user controls their own role — any role, not just
 * admin) or a boolean privilege flag flipped true. softHit = the update echoed
 * an injected privileged value but persistence couldn't be independently confirmed.
 */
function detectElevation(
  before: Signals | null,
  after: Signals | null,
  responseBody: string,
  payload: Record<string, unknown>,
): { vulnerable: boolean; softHit: boolean; detail: string } {
  const injected = injectedValues(payload);
  if (after) {
    for (const key of ROLE_KEYS) {
      const a = after.values[key];
      if (a === undefined) continue;
      const b = before?.values[key];
      if (a === b) continue; // unchanged → server ignored it (secure)
      // Changed, and the new value is one we supplied (or a privilege flag is now true).
      if (matchesInjected(a, injected) || isPrivilegeFlag(key, a)) {
        return { vulnerable: true, softHit: false, detail: `${key}: ${b ?? '∅'} → ${a}` };
      }
    }
  }
  // No independent persistence proof, but the update response echoed an injected value.
  const echoed = signalsFromBody(responseBody);
  for (const key of ROLE_KEYS) {
    const v = echoed.values[key];
    if (v && (matchesInjected(v, injected) || isPrivilegeFlag(key, v))) {
      return { vulnerable: false, softHit: true, detail: `${key} echoed ${v}` };
    }
  }
  return { vulnerable: false, softHit: false, detail: '' };
}

/** Lowercased set of scalar values we injected (role strings + "true"). */
function injectedValues(payload: Record<string, unknown>): Set<string> {
  const out = new Set<string>();
  for (const v of Object.values(payload)) {
    if (Array.isArray(v)) v.forEach((x) => out.add(String(x).toLowerCase()));
    else out.add(String(v).toLowerCase());
  }
  return out;
}

function matchesInjected(value: string, injected: Set<string>): boolean {
  const s = value.toLowerCase();
  if (injected.has(s)) return true;
  // Array/JSON-ish read-back like ["teacher"] — check membership loosely.
  return [...injected].some((inj) => inj.length > 2 && s.includes(inj));
}

function isPrivilegeFlag(key: string, value: string): boolean {
  const flagKeys = ['isadmin', 'is_admin', 'admin', 'isstaff', 'issuperuser', 'is_superuser'];
  return flagKeys.includes(key) && /true|1/i.test(value);
}

async function readSignals(
  transport: Transport,
  url: string,
  opts: ProfileEscalationOptions,
): Promise<Signals | null> {
  try {
    const r = await transport({
      url,
      method: 'GET',
      account: opts.account,
      session: opts.session,
      extraAllowedHosts: opts.extraAllowedHosts,
    });
    if (r.status < 200 || r.status >= 300) return null;
    return signalsFromBody(r.body);
  } catch {
    return null;
  }
}

/** Pull role-ish key/value pairs out of a JSON body (flattened, lowercased keys). */
function signalsFromBody(body: string): Signals {
  const values: Record<string, string> = {};
  let doc: unknown;
  try {
    doc = JSON.parse(body);
  } catch {
    return { values };
  }
  const visit = (obj: unknown): void => {
    if (!obj || typeof obj !== 'object') return;
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      const key = k.toLowerCase();
      if (ROLE_KEYS.includes(key)) {
        values[key] = Array.isArray(v) ? JSON.stringify(v) : String(v);
      }
      if (v && typeof v === 'object') visit(v);
    }
  };
  visit(doc);
  return { values };
}

function pickSelfReadUrl(endpoints: AttackSurfaceEndpoint[]): string | null {
  // Prefer a discovered GET self endpoint; else fall back to a conventional one.
  const got = endpoints.find(
    (e) => e.method.toUpperCase() === 'GET' && /\/(me|account|profile|users\/me)(\/|$)/i.test(safePath(e.url)),
  );
  if (got) return concrete(got.url);
  const any = endpoints[0];
  if (!any) return null;
  try {
    return new URL('/me', new URL(any.url).origin).toString();
  } catch {
    return null;
  }
}

function concrete(url: string): string {
  // Replace OpenAPI template ids with a benign value so the URL is requestable.
  return url.replace(/%7B[^%]*%7D/gi, 'me').replace(/\{[^}]+\}/g, 'me');
}

function safePath(url: string): string {
  try {
    return new URL(url, 'http://placeholder.local').pathname;
  } catch {
    return url;
  }
}

function shortId(url: string): string {
  let h = 0;
  for (let i = 0; i < url.length; i++) h = (Math.imul(31, h) + url.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
}
