import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetEnvCacheForTests } from '../config/env.js';

// Mock the network layer so the brute-forcer never makes real requests.
const send = vi.fn();
vi.mock('../core/scanner/http-request.js', () => ({
  sendRequest: (input: unknown) => send(input),
}));

import { bruteForceNumericCode } from '../core/scanner/brute-forcer.js';
import { AuditLogger } from '../core/logging/audit-logger.js';

const ORIGINAL = process.env;

function res(status: number, body = '', headers: Record<string, string> = {}) {
  return { status, headers, body, setCookies: [], durationMs: 1 };
}

function baseSpec(over: Record<string, unknown> = {}) {
  return {
    url: 'http://localhost:3000/auth/verify',
    method: 'POST',
    codeParam: 'code',
    codeLength: 2, // 100-key space keeps tests fast
    staticFields: { email: 'x@smcp-test.invalid' },
    audit: new AuditLogger('test'),
    ...over,
  };
}

beforeEach(() => {
  process.env = { ...ORIGINAL, SCAN_RATELIMIT_SAMPLE: '5', SCAN_BRUTE_CONCURRENCY: '4' };
  resetEnvCacheForTests();
  send.mockReset();
});
afterEach(() => {
  process.env = ORIGINAL;
  resetEnvCacheForTests();
});

describe('bruteForceNumericCode', () => {
  it('aborts as SECURE when the endpoint throttles in the precheck', async () => {
    send.mockResolvedValue(res(429, '', { 'retry-after': '30' }));
    const r = await bruteForceNumericCode(baseSpec() as never);
    expect(r.rateLimited).toBe(true);
    expect(r.aborted).toBe(true);
    expect(r.found).toBeUndefined();
  });

  it('cracks the code when there is no rate limiting', async () => {
    send.mockImplementation((input: { body?: string }) => {
      const ok = typeof input.body === 'string' && input.body.includes('"code":"42"');
      return Promise.resolve(ok ? res(200, '{"verified":true}') : res(400, 'bad code'));
    });
    const r = await bruteForceNumericCode(baseSpec() as never);
    expect(r.found).toBe('42');
    expect(r.rateLimited).toBe(false);
    expect(r.aborted).toBe(false);
  });

  it('sweeps without success and reports no throttling when nothing matches', async () => {
    send.mockResolvedValue(res(400, 'nope'));
    const r = await bruteForceNumericCode(baseSpec() as never);
    expect(r.found).toBeUndefined();
    expect(r.aborted).toBe(false);
    expect(r.note).toMatch(/no throttling/i);
  });

  it('refuses an out-of-scope target before any request', async () => {
    const r = await bruteForceNumericCode(baseSpec({ url: 'https://api.example.com/verify' }) as never);
    expect(r.aborted).toBe(true);
    expect(r.abortReason).toMatch(/policy/i);
    expect(send).not.toHaveBeenCalled();
  });
});
