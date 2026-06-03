import { describe, it, expect, beforeEach } from 'vitest';
import {
  probeAccessControl,
  BYPASS_HEADERS,
  isAuthorized,
  isGated,
  isAdminRole,
  bodyDiffers,
} from '../core/scanner/access-control-prober.js';
import { resetEnvCacheForTests } from '../config/env.js';
import { AuditLogger } from '../core/logging/audit-logger.js';
import type { SendRequestInput, SendRequestResult } from '../core/scanner/http-request.js';
import type { AttackSurfaceEndpoint } from '../types/scan.types.js';

beforeEach(() => resetEnvCacheForTests());
const audit = new AuditLogger('test');

function ep(url: string, over: Partial<AttackSurfaceEndpoint> = {}): AttackSurfaceEndpoint {
  return {
    url,
    method: 'GET',
    hasQueryParams: false,
    hasPathId: false,
    authGated: false,
    hasForm: false,
    isUpload: false,
    looksAdmin: false,
    isApiLike: true,
    applicableGoals: [],
    ...over,
  };
}

function r(status: number, body = ''): SendRequestResult {
  // Default bodies: a short denial vs a longer "real content" payload so the
  // prober's body-diff guard can distinguish a genuine bypass from a soft-200.
  const b = body || (status >= 200 && status < 300 ? 'X'.repeat(500) : '{"err":401}');
  return { status, headers: {}, body: b, setCookies: [], durationMs: 1 };
}

describe('classifiers', () => {
  it('isAuthorized / isGated / isAdminRole', () => {
    expect(isAuthorized(200)).toBe(true);
    expect(isAuthorized(401)).toBe(false);
    expect(isGated(403)).toBe(true);
    expect(isAdminRole('admin')).toBe(true);
    expect(isAdminRole('superuser')).toBe(true);
    expect(isAdminRole('member')).toBe(false);
  });
  it('has a meaningful set of bypass headers', () => {
    expect(BYPASS_HEADERS.length).toBeGreaterThan(8);
    expect(BYPASS_HEADERS.some((h) => 'x-original-url' in h.headers)).toBe(true);
  });
  it('bodyDiffers ignores soft-200s with baseline-sized bodies', () => {
    expect(bodyDiffers(11, 11)).toBe(false);
    expect(bodyDiffers(11, 0)).toBe(false);
    expect(bodyDiffers(11, 500)).toBe(true);
  });
});

describe('probeAccessControl (read-only BFLA)', () => {
  it('flags an admin route reachable without authentication', async () => {
    const transport = async (): Promise<SendRequestResult> => r(200); // everything open
    const findings = await probeAccessControl({
      endpoints: [ep('http://localhost:3000/api/admin/users', { looksAdmin: true })],
      audit,
      transport,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('critical');
    expect(findings[0]!.title).toMatch(/Unauthenticated access/);
  });

  it('flags a header-trick bypass (401 normally, 200 with X-Original-URL)', async () => {
    const transport = async (input: SendRequestInput): Promise<SendRequestResult> => {
      const tricked = input.headers && Object.keys(input.headers).length > 0;
      return r(tricked ? 200 : 401);
    };
    const findings = await probeAccessControl({
      endpoints: [ep('http://localhost:3000/api/admin/users', { looksAdmin: true, authGated: true })],
      audit,
      transport,
    });
    expect(findings.some((f) => /bypassed via request header/i.test(f.title))).toBe(true);
    expect(findings[0]!.severity).toBe('critical');
  });

  it('stays quiet when the route is properly gated and no header trick works', async () => {
    const transport = async (): Promise<SendRequestResult> => r(401);
    const findings = await probeAccessControl({
      endpoints: [ep('http://localhost:3000/api/admin/users', { looksAdmin: true, authGated: true })],
      audit,
      transport,
    });
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag a soft-200 whose body matches the gated baseline', async () => {
    // 401 then a 200 of the SAME small size (an error page rendered with 200).
    const transport = async (input: SendRequestInput): Promise<SendRequestResult> => {
      const tricked = input.headers && Object.keys(input.headers).length > 0;
      return tricked ? r(200, '{"err":401}') : r(401, '{"err":401}');
    };
    const findings = await probeAccessControl({
      endpoints: [ep('http://localhost:3000/api/admin/users', { looksAdmin: true, authGated: true })],
      audit,
      transport,
    });
    expect(findings).toHaveLength(0);
  });

  it('flags a non-admin role reaching an admin route (cross-role differential)', async () => {
    // Unauthenticated → 401; member token → 200 (BFLA).
    const transport = async (input: SendRequestInput): Promise<SendRequestResult> => {
      if (input.account?.role === 'member') return r(200);
      if (input.headers && Object.keys(input.headers).length > 0) return r(401);
      return r(401);
    };
    const findings = await probeAccessControl({
      endpoints: [ep('http://localhost:3000/api/admin/users', { looksAdmin: true, authGated: true })],
      accounts: [{ role: 'member', token: 'x' }],
      audit,
      transport,
    });
    expect(findings.some((f) => /Non-admin role can access admin route/i.test(f.title))).toBe(true);
  });

  it('substitutes {id} template params with a concrete value before probing', async () => {
    let seen = '';
    const transport = async (input: SendRequestInput): Promise<SendRequestResult> => {
      seen = input.url;
      return r(401);
    };
    await probeAccessControl({
      endpoints: [ep('http://localhost:3000/api/admin/users/{id}/account-status', { looksAdmin: true })],
      audit,
      transport,
    });
    expect(seen).toBe('http://localhost:3000/api/admin/users/1/account-status');
  });
});
