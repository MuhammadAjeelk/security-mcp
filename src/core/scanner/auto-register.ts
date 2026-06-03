import { getEnv } from '../../config/env.js';
import { AuditLogger } from '../logging/audit-logger.js';
import {
  sendRequest,
  cookiesFromSetCookie,
  type SendRequestResult,
  type Transport,
} from './http-request.js';
import type {
  AuthSession,
  AutoRegisterResult,
  DiscoveredForm,
  RegisteredAccount,
  ScanEvidence,
  TestAccount,
} from '../../types/scan.types.js';

/**
 * Self-registration + self-healing identity routine.
 *
 * Establishes the attacker's own throwaway identities so that authenticated,
 * access-control, IDOR/BOLA and tenant-isolation checks can actually run when
 * the operator supplied no credentials. It ALSO probes the registration
 * boundary for mass-assignment privilege escalation (submitting role/admin
 * fields the form never advertised) — a classic critical bug.
 *
 * Strictly own-account only: it never touches existing users or data. "Self
 * healing" means: when a registration attempt fails, it retries with alternate
 * field-name guesses and a content-type fallback before giving up, and reports
 * exactly what it tried.
 */
export interface AutoRegisterOptions {
  evidence: Pick<ScanEvidence, 'targetUrl' | 'forms' | 'endpoints'>;
  extraAllowedHosts?: string[];
  audit: AuditLogger;
  /** Injectable transport (tests). Defaults to the real policy-checked sender. */
  transport?: Transport;
  /** Deterministic suffix generator (tests). Defaults to a timestamp+random. */
  suffix?: () => string;
}

const SIGNUP_PATH_CANDIDATES = [
  '/api/auth/register',
  '/api/register',
  '/api/users',
  '/api/signup',
  '/auth/register',
  '/register',
  '/signup',
  '/users',
];

const ESCALATION_FIELDS: Array<{ field: string; value: unknown }> = [
  { field: 'role', value: 'admin' },
  { field: 'is_admin', value: true },
  { field: 'isAdmin', value: true },
  { field: 'admin', value: true },
  { field: 'accountType', value: 'admin' },
  { field: 'permissions', value: ['*'] },
  { field: 'groups', value: ['administrators'] },
];

export async function autoRegister(opts: AutoRegisterOptions): Promise<AutoRegisterResult> {
  const env = getEnv();
  const transport = opts.transport ?? sendRequest;
  const suffix = opts.suffix ?? defaultSuffix;
  const maxAccounts = env.SCAN_REGISTER_MAX_ACCOUNTS;

  const result: AutoRegisterResult = {
    signupFound: false,
    accounts: [],
    testAccounts: [],
    notes: [],
  };

  if (maxAccounts <= 0) {
    result.notes.push('Self-registration disabled (SCAN_REGISTER_MAX_ACCOUNTS=0).');
    return result;
  }

  const signupUrls = candidateSignupUrls(opts.evidence);
  if (signupUrls.length === 0) {
    result.notes.push('No signup form or registration endpoint discovered.');
    return result;
  }

  // Attempt 1: a plain throwaway account (a "normal" user identity).
  const normal = await tryRegister({
    signupUrls,
    suffix,
    transport,
    opts,
    role: 'self-registered',
    escalation: null,
    result,
  });
  if (normal) {
    result.accounts.push(normal.account);
    result.testAccounts.push(toTestAccount(normal.account));
    result.signupFound = true;
    result.signupUrl = normal.signupUrl;
  }

  // Attempt 2 (if we have a working signup): probe mass-assignment escalation.
  if (result.signupFound && result.accounts.length < maxAccounts) {
    for (const esc of ESCALATION_FIELDS) {
      if (result.accounts.length >= maxAccounts) break;
      const elevated = await tryRegister({
        signupUrls: [result.signupUrl!, ...signupUrls],
        suffix,
        transport,
        opts,
        role: 'self-registered-admin-attempt',
        escalation: esc,
        result,
      });
      if (!elevated) continue;
      const priv = await checkPrivilege({
        session: elevated.account.session,
        body: elevated.body,
        transport,
        opts,
      });
      if (priv.privileged) {
        elevated.account.privileged = true;
        elevated.account.escalatedVia = esc.field;
        result.privilegeEscalation = {
          field: esc.field,
          value: String(esc.value),
          evidence: priv.evidence,
        };
        result.accounts.push(elevated.account);
        result.testAccounts.push(toTestAccount(elevated.account));
        result.notes.push(
          `PRIVILEGE ESCALATION: server honored mass-assigned "${esc.field}=${String(esc.value)}" at signup.`,
        );
        break; // one confirmed escalation is enough to prove the bug
      }
      result.notes.push(`Mass-assignment "${esc.field}" submitted but not honored (good).`);
      // Don't keep a non-elevated duplicate account around beyond the budget.
      break;
    }
  }

  return result;
}

interface TryRegisterArgs {
  signupUrls: string[];
  suffix: () => string;
  transport: Transport;
  opts: AutoRegisterOptions;
  role: string;
  escalation: { field: string; value: unknown } | null;
  result: AutoRegisterResult;
}

/**
 * Try to register one account, self-healing across signup URLs, field-name
 * guesses, and JSON↔form content types. Returns the created account or null.
 */
async function tryRegister(args: TryRegisterArgs): Promise<{
  account: RegisteredAccount;
  signupUrl: string;
  body: string;
} | null> {
  const fieldSets = candidateFieldMappings(args.opts.evidence);
  const encodings: Array<'json' | 'form'> = ['json', 'form'];

  for (const url of dedupe(args.signupUrls)) {
    for (const fields of fieldSets) {
      for (const encoding of encodings) {
        const email = `smcp_${args.suffix()}@smcp-test.invalid`;
        const password = `Smcp!${args.suffix()}aA1`;
        const payload = buildPayload(fields, email, password, args.escalation);
        let res: SendRequestResult;
        try {
          res = await args.transport({
            url,
            method: 'POST',
            headers: { 'content-type': contentType(encoding) },
            body: encodeBody(encoding, payload),
            extraAllowedHosts: args.opts.extraAllowedHosts,
          });
        } catch (err) {
          args.opts.audit.event('auto-register.error', {
            url,
            reason: err instanceof Error ? err.message : String(err),
          });
          continue;
        }

        if (isRegistrationSuccess(res)) {
          const session = sessionFromResponse(res);
          args.opts.audit.event('auto-register.success', { url, role: args.role, status: res.status });
          return {
            account: { role: args.role, email, privileged: false, session },
            signupUrl: url,
            body: res.body,
          };
        }
        // Self-healing signal: a validation error often names the real fields.
        const hinted = fieldsFromValidationError(res.body);
        if (hinted.length > 0) {
          args.result.notes.push(
            `Signup at ${pathOf(url)} hinted required fields: ${hinted.join(', ')} (retrying).`,
          );
        }
      }
    }
  }
  return null;
}

interface CheckPrivilegeArgs {
  session: AuthSession;
  body: string;
  transport: Transport;
  opts: AutoRegisterOptions;
}

/** Read back the new account's profile/JWT to see if elevated privileges stuck. */
async function checkPrivilege(
  args: CheckPrivilegeArgs,
): Promise<{ privileged: boolean; evidence: string }> {
  // First, the registration response body itself (often echoes the user).
  const fromBody = detectPrivilege(args.body);
  if (fromBody.privileged) return fromBody;

  // JWT claims, if a bearer token was issued.
  if (args.session.bearerToken) {
    const claims = decodeJwtClaims(args.session.bearerToken);
    if (claims) {
      const fromJwt = detectPrivilege(JSON.stringify(claims));
      if (fromJwt.privileged) {
        return { privileged: true, evidence: `JWT claims indicate privilege: ${fromJwt.evidence}` };
      }
    }
  }

  // Otherwise hit common self-profile endpoints with the new session.
  const origin = safeOrigin(args.opts.evidence.targetUrl);
  if (!origin) return { privileged: false, evidence: '' };
  for (const path of ['/api/me', '/me', '/api/account', '/account', '/api/users/me', '/profile']) {
    let res: SendRequestResult;
    try {
      res = await args.transport({
        url: origin + path,
        method: 'GET',
        session: args.session,
        extraAllowedHosts: args.opts.extraAllowedHosts,
      });
    } catch {
      continue;
    }
    if (res.status >= 200 && res.status < 300) {
      const det = detectPrivilege(res.body);
      if (det.privileged) {
        return { privileged: true, evidence: `${path}: ${det.evidence}` };
      }
    }
  }
  return { privileged: false, evidence: '' };
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested)
// ---------------------------------------------------------------------------

/** Build the ordered list of URLs to try the signup against. */
export function candidateSignupUrls(
  evidence: Pick<ScanEvidence, 'targetUrl' | 'forms' | 'endpoints'>,
): string[] {
  const origin = safeOrigin(evidence.targetUrl);
  const urls: string[] = [];

  // 1. Forms that look like signup.
  for (const form of evidence.forms) {
    if (!looksLikeSignupForm(form)) continue;
    const action = form.action || form.pageUrl;
    const abs = absolutize(action, form.pageUrl || evidence.targetUrl);
    if (abs) urls.push(abs);
  }

  // 2. Discovered endpoints whose path screams registration.
  for (const e of evidence.endpoints) {
    if (/\b(register|signup|sign-up)\b/i.test(e.url) && /post/i.test(e.method)) urls.push(e.url);
    else if (/(register|signup)/i.test(e.url)) urls.push(e.url);
  }

  // 3. Conventional fallbacks.
  if (origin) for (const p of SIGNUP_PATH_CANDIDATES) urls.push(origin + p);

  return dedupe(urls);
}

export function looksLikeSignupForm(form: DiscoveredForm): boolean {
  const hay = (form.action ?? '') + ' ' + form.fields.join(' ');
  const hasPassword = form.fields.some((f) => /pass(word|wd)?/i.test(f));
  const signupWord = /(register|signup|sign-up|create.?account|join)/i.test(hay);
  // A form with both a password and a confirm-password is almost certainly signup.
  const confirm = form.fields.some((f) => /(confirm|repeat|verify).*pass|pass.*(confirm|2)/i.test(f));
  return (hasPassword && (signupWord || confirm)) || signupWord;
}

/** Candidate field-name mappings, ordered most-conventional first. */
export function candidateFieldMappings(
  evidence: Pick<ScanEvidence, 'forms'>,
): Array<{ email: string; password: string; confirm?: string; name?: string }> {
  const sets: Array<{ email: string; password: string; confirm?: string; name?: string }> = [];

  // Derive from a discovered signup form's actual field names first.
  for (const form of evidence.forms) {
    if (!looksLikeSignupForm(form)) continue;
    const pwRe = /pass(word|wd)?|passwd|pwd/i;
    const email = form.fields.find((f) => /e-?mail|user(name)?|login/i.test(f));
    const password = form.fields.find((f) => pwRe.test(f) && !/confirm|repeat|verify|2/i.test(f));
    const confirm = form.fields.find((f) => /(confirm|repeat|verify|2)/i.test(f) && pwRe.test(f));
    const name = form.fields.find((f) => /\b(name|full.?name|display)\b/i.test(f));
    if (email && password) sets.push({ email, password, confirm, name });
  }

  // Conventional fallbacks.
  sets.push({ email: 'email', password: 'password', confirm: 'password_confirmation', name: 'name' });
  sets.push({ email: 'email', password: 'password' });
  sets.push({ email: 'username', password: 'password' });
  sets.push({ email: 'user', password: 'pass' });
  return dedupeMappings(sets);
}

export function buildPayload(
  fields: { email: string; password: string; confirm?: string; name?: string },
  email: string,
  password: string,
  escalation: { field: string; value: unknown } | null,
): Record<string, unknown> {
  const payload: Record<string, unknown> = { [fields.email]: email, [fields.password]: password };
  if (fields.confirm) payload[fields.confirm] = password;
  if (fields.name) payload[fields.name] = 'SMCP Test';
  if (escalation) payload[escalation.field] = escalation.value;
  return payload;
}

export function isRegistrationSuccess(res: SendRequestResult): boolean {
  if (res.status === 200 || res.status === 201) {
    return !/error|invalid|fail|exists|denied/i.test(res.body.slice(0, 500));
  }
  // A 302 to a logged-in area with a session cookie also counts.
  if (res.status === 302 && res.setCookies.length > 0) return true;
  return false;
}

export function sessionFromResponse(res: SendRequestResult): AuthSession {
  const session: AuthSession = { origin: 'auto-registered' };
  const cookies = cookiesFromSetCookie(res.setCookies);
  if (Object.keys(cookies).length > 0) session.cookies = cookies;
  const token = tokenFromBody(res.body);
  if (token) session.bearerToken = token;
  return session;
}

/** Extract a bearer/JWT/access token from a JSON registration response. */
export function tokenFromBody(body: string): string | undefined {
  try {
    const obj = JSON.parse(body) as Record<string, unknown>;
    for (const key of ['token', 'accessToken', 'access_token', 'jwt', 'idToken', 'id_token']) {
      const v = obj[key];
      if (typeof v === 'string' && v.length > 10) return v;
    }
    // nested data.token
    const data = obj['data'];
    if (data && typeof data === 'object') {
      for (const key of ['token', 'accessToken', 'access_token', 'jwt']) {
        const v = (data as Record<string, unknown>)[key];
        if (typeof v === 'string' && v.length > 10) return v;
      }
    }
  } catch {
    // not JSON — look for a raw JWT pattern
    const m = body.match(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
    if (m) return m[0];
  }
  return undefined;
}

/** Heuristically decide whether a profile/JSON blob indicates an admin/privileged account. */
export function detectPrivilege(body: string): { privileged: boolean; evidence: string } {
  const re =
    /"(role|roles|is_admin|isAdmin|admin|accountType|account_type)"\s*:\s*("?(admin|administrator|superuser|root|true)"?|\[[^\]]*"(admin|administrator|\*)"[^\]]*\])/i;
  const m = body.match(re);
  if (m) return { privileged: true, evidence: m[0].slice(0, 120) };
  return { privileged: false, evidence: '' };
}

/** Parse field names out of a validation-error response so we can self-heal. */
export function fieldsFromValidationError(body: string): string[] {
  const fields = new Set<string>();
  // JSON shapes: {"errors":{"email":["required"]}} or {"message":"email is required"}
  for (const m of body.matchAll(/"([a-zA-Z_][\w]{1,40})"\s*:\s*\[?\s*"?[^"]*(required|missing|invalid)/gi)) {
    if (m[1] && !/error|message|status|code/i.test(m[1])) fields.add(m[1]);
  }
  for (const m of body.matchAll(/\b([a-zA-Z_][\w]{1,40})\b\s+is\s+(required|missing)/gi)) {
    if (m[1]) fields.add(m[1]);
  }
  return [...fields];
}

export function decodeJwtClaims(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const json = Buffer.from(parts[1]!.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function toTestAccount(account: RegisteredAccount): TestAccount {
  return {
    role: account.role,
    email: account.email,
    token: account.session.bearerToken,
    cookies: account.session.cookies,
  };
}

function contentType(encoding: 'json' | 'form'): string {
  return encoding === 'json' ? 'application/json' : 'application/x-www-form-urlencoded';
}

function encodeBody(encoding: 'json' | 'form', payload: Record<string, unknown>): string {
  if (encoding === 'json') return JSON.stringify(payload);
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(payload)) {
    params.set(k, Array.isArray(v) ? v.join(',') : String(v));
  }
  return params.toString();
}

let counter = 0;
function defaultSuffix(): string {
  counter += 1;
  return `${Date.now().toString(36)}${counter}`;
}

function dedupe(list: string[]): string[] {
  return [...new Set(list)];
}

function dedupeMappings<T extends Record<string, unknown>>(list: T[]): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const m of list) {
    const key = JSON.stringify(m);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(m);
  }
  return out;
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

function pathOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}
