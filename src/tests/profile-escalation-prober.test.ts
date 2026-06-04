import { describe, expect, it } from 'vitest';
import { probeProfileEscalation } from '../core/scanner/profile-escalation-prober.js';
import { AuditLogger } from '../core/logging/audit-logger.js';
import type { AttackSurfaceEndpoint } from '../types/scan.types.js';
import type { SendRequestInput, SendRequestResult } from '../core/scanner/http-request.js';

function ep(url: string, method: string): AttackSurfaceEndpoint {
  return {
    url, method,
    hasQueryParams: false, hasPathId: false, authGated: true, hasForm: false,
    isUpload: false, looksAdmin: false, isApiLike: true, applicableGoals: [],
  };
}

function resp(status: number, body: string): SendRequestResult {
  return { status, headers: { 'content-type': 'application/json' }, body, setCookies: [], durationMs: 1 };
}

const ENDPOINTS = [
  ep('http://localhost:3000/api/me', 'GET'),
  ep('http://localhost:3000/api/me', 'PATCH'),
];

const ACCOUNT = { role: 'user', token: 'jwt-abc' };

describe('probeProfileEscalation', () => {
  it('flags critical when a self-update changes the role to an injected value (student→higher)', async () => {
    let role = 'student';
    const transport = async (input: SendRequestInput): Promise<SendRequestResult> => {
      if (input.method === 'GET') return resp(200, JSON.stringify({ id: 1, role }));
      const body = JSON.parse(input.body ?? '{}') as { role?: string };
      if (body.role) role = body.role; // server honors client-supplied role (the bug)
      return resp(200, JSON.stringify({ ok: true }));
    };
    const findings = await probeProfileEscalation({
      endpoints: ENDPOINTS, account: ACCOUNT, audit: new AuditLogger('t'), transport,
    });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.severity).toBe('critical');
    expect(findings[0]!.title).toMatch(/Privilege escalation via profile/i);
  });

  it('stays clean when the server ignores the role field on self-update', async () => {
    const role = 'student';
    const transport = async (input: SendRequestInput): Promise<SendRequestResult> => {
      if (input.method === 'GET') return resp(200, JSON.stringify({ id: 1, role }));
      return resp(200, JSON.stringify({ id: 1, role })); // echoes ORIGINAL role, ignores injection
    };
    const findings = await probeProfileEscalation({
      endpoints: ENDPOINTS, account: ACCOUNT, audit: new AuditLogger('t'), transport,
    });
    expect(findings).toEqual([]);
  });

  it('does nothing without an authenticated identity', async () => {
    let called = false;
    const transport = async (): Promise<SendRequestResult> => {
      called = true;
      return resp(200, '{}');
    };
    const findings = await probeProfileEscalation({
      endpoints: ENDPOINTS, audit: new AuditLogger('t'), transport,
    });
    expect(findings).toEqual([]);
    expect(called).toBe(false);
  });
});
