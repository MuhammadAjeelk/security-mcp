import { describe, it, expect, beforeEach } from 'vitest';
import {
  autoRegister,
  candidateSignupUrls,
  looksLikeSignupForm,
  candidateFieldMappings,
  buildPayload,
  isRegistrationSuccess,
  tokenFromBody,
  detectPrivilege,
  fieldsFromValidationError,
  decodeJwtClaims,
} from '../core/scanner/auto-register.js';
import { resetEnvCacheForTests } from '../config/env.js';
import { AuditLogger } from '../core/logging/audit-logger.js';
import type { SendRequestInput, SendRequestResult } from '../core/scanner/http-request.js';

beforeEach(() => {
  resetEnvCacheForTests();
});

const audit = new AuditLogger('test');

function jsonRes(status: number, body: unknown, setCookies: string[] = []): SendRequestResult {
  return {
    status,
    headers: { 'content-type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
    setCookies,
    durationMs: 1,
  };
}

describe('signup form detection', () => {
  it('recognizes a register form by word + password', () => {
    expect(
      looksLikeSignupForm({ pageUrl: 'x', action: '/register', method: 'POST', fields: ['email', 'password'] }),
    ).toBe(true);
  });
  it('recognizes by confirm-password pair', () => {
    expect(
      looksLikeSignupForm({
        pageUrl: 'x',
        action: '/create',
        method: 'POST',
        fields: ['email', 'password', 'password_confirmation'],
      }),
    ).toBe(true);
  });
  it('rejects a plain login form', () => {
    expect(
      looksLikeSignupForm({ pageUrl: 'x', action: '/login', method: 'POST', fields: ['email', 'password'] }),
    ).toBe(false);
  });
});

describe('candidate signup urls', () => {
  it('prioritizes discovered forms and endpoints, then conventional fallbacks', () => {
    const urls = candidateSignupUrls({
      targetUrl: 'http://localhost:3000/',
      forms: [{ pageUrl: 'http://localhost:3000/join', action: '/api/register', method: 'POST', fields: ['email', 'password'] }],
      endpoints: [{ url: 'http://localhost:3000/signup', method: 'POST', source: 'crawler' }],
    });
    expect(urls[0]).toBe('http://localhost:3000/api/register');
    expect(urls).toContain('http://localhost:3000/signup');
    expect(urls).toContain('http://localhost:3000/api/auth/register');
  });
});

describe('field mapping + payload', () => {
  it('derives field names from a discovered form', () => {
    const sets = candidateFieldMappings({
      forms: [{ pageUrl: 'x', action: '/register', method: 'POST', fields: ['userEmail', 'pwd', 'pwd_confirm', 'fullName'] }],
    });
    expect(sets[0]).toMatchObject({ email: 'userEmail', password: 'pwd' });
  });
  it('builds a payload including an escalation field', () => {
    const p = buildPayload({ email: 'email', password: 'password' }, 'a@b.invalid', 'pw', {
      field: 'role',
      value: 'admin',
    });
    expect(p).toEqual({ email: 'a@b.invalid', password: 'pw', role: 'admin' });
  });
});

describe('response parsing helpers', () => {
  it('detects registration success vs error body', () => {
    expect(isRegistrationSuccess(jsonRes(201, { id: 1 }))).toBe(true);
    expect(isRegistrationSuccess(jsonRes(200, { error: 'email exists' }))).toBe(false);
    expect(isRegistrationSuccess(jsonRes(302, {}, ['sid=abc; Path=/']))).toBe(true);
  });
  it('extracts tokens from json and raw jwt', () => {
    expect(tokenFromBody(JSON.stringify({ accessToken: 'a'.repeat(20) }))).toBe('a'.repeat(20));
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig';
    expect(tokenFromBody(`prefix ${jwt} suffix`)).toBe(jwt);
  });
  it('detects privilege in a profile body', () => {
    expect(detectPrivilege('{"role":"admin"}').privileged).toBe(true);
    expect(detectPrivilege('{"is_admin":true}').privileged).toBe(true);
    expect(detectPrivilege('{"role":"user"}').privileged).toBe(false);
  });
  it('decodes jwt claims', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from('{"role":"admin"}').toString('base64') + '.sig';
    expect(decodeJwtClaims(jwt)).toEqual({ role: 'admin' });
  });
  it('extracts hinted fields from validation errors', () => {
    const hinted = fieldsFromValidationError('{"errors":{"username":["required"],"age":["required"]}}');
    expect(hinted).toContain('username');
    expect(hinted).toContain('age');
  });
});

describe('autoRegister orchestration (stub transport)', () => {
  it('registers a normal account and detects mass-assignment escalation', async () => {
    const calls: SendRequestInput[] = [];
    const transport = async (input: SendRequestInput): Promise<SendRequestResult> => {
      calls.push(input);
      const body = input.body ?? '';
      if (input.method === 'POST' && input.url.endsWith('/api/register')) {
        // Honor any role=admin sent (the bug). Otherwise create a normal user.
        const isAdmin = /"role":"admin"|role=admin/.test(body);
        return jsonRes(201, { id: 1, role: isAdmin ? 'admin' : 'user', token: 'x'.repeat(20) });
      }
      return jsonRes(404, { error: 'not found' });
    };

    const result = await autoRegister({
      evidence: {
        targetUrl: 'http://localhost:3000/',
        forms: [{ pageUrl: 'http://localhost:3000/', action: '/api/register', method: 'POST', fields: ['email', 'password'] }],
        endpoints: [],
      },
      audit,
      transport,
      suffix: (() => {
        let n = 0;
        return () => `t${n++}`;
      })(),
    });

    expect(result.signupFound).toBe(true);
    expect(result.accounts.length).toBeGreaterThanOrEqual(1);
    expect(result.privilegeEscalation).toBeDefined();
    expect(result.privilegeEscalation?.field).toBe('role');
    expect(result.testAccounts.some((a) => a.role.includes('admin'))).toBe(true);
  });

  it('reports gracefully when no signup surface exists', async () => {
    const transport = async (): Promise<SendRequestResult> => jsonRes(404, { error: 'nope' });
    const result = await autoRegister({
      evidence: { targetUrl: 'http://localhost:3000/', forms: [], endpoints: [] },
      audit,
      transport,
    });
    // Conventional fallbacks are still tried; none succeed → no accounts.
    expect(result.accounts).toHaveLength(0);
    expect(result.privilegeEscalation).toBeUndefined();
  });
});
