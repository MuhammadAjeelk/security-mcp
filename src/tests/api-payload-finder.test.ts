import { describe, it, expect, beforeEach } from 'vitest';
import {
  findApiPayload,
  seedFields,
  placeholderFor,
} from '../core/scanner/api-payload-finder.js';
import { resetEnvCacheForTests } from '../config/env.js';
import { AuditLogger } from '../core/logging/audit-logger.js';
import type { SendRequestInput, SendRequestResult } from '../core/scanner/http-request.js';

beforeEach(() => resetEnvCacheForTests());
const audit = new AuditLogger('test');

function res(status: number, body: unknown, headers: Record<string, string> = {}): SendRequestResult {
  return {
    status,
    headers,
    body: typeof body === 'string' ? body : JSON.stringify(body),
    setCookies: [],
    durationMs: 1,
  };
}

describe('placeholder typing', () => {
  it('picks type-appropriate benign values', () => {
    expect(placeholderFor('email')).toBe('smcp@smcp-test.invalid');
    expect(placeholderFor('password')).toBe('Smcp!test1A');
    expect(placeholderFor('quantity')).toBe(1);
    expect(placeholderFor('isActive')).toBe(true);
    expect(placeholderFor('userId')).toBe('1');
  });
});

describe('seed fields', () => {
  it('guesses login fields from the path', () => {
    const seeded = seedFields('http://localhost:3000/api/auth/login', new Map());
    expect(seeded).toContain('email');
    expect(seeded).toContain('password');
  });
});

describe('findApiPayload: iterative learning', () => {
  it('learns required fields from successive validation errors until success', async () => {
    const transport = async (input: SendRequestInput): Promise<SendRequestResult> => {
      if (input.method === 'OPTIONS') return res(204, '', { allow: 'GET, POST, OPTIONS' });
      const body = input.body ?? '';
      const has = (f: string) => body.includes(`"${f}"`);
      // Server reveals one missing field at a time.
      if (!has('email')) return res(422, { errors: { email: ['required'] } });
      if (!has('password')) return res(422, { errors: { password: ['required'] } });
      if (!has('age')) return res(422, { message: 'age is required' });
      return res(201, { id: 1 });
    };

    const result = await findApiPayload({
      url: 'http://localhost:3000/api/users',
      audit,
      transport,
    });

    expect(result.method).toBe('POST');
    expect(result.allowedMethods).toContain('POST');
    expect(result.succeeded).toBe(true);
    expect(result.requiredFields).toEqual(expect.arrayContaining(['email', 'password', 'age']));
    expect(result.inferredPayload.email).toBe('smcp@smcp-test.invalid');
    expect(result.finalStatus).toBe(201);
  });

  it('falls back to seeded fields when the error gives no hints', async () => {
    const transport = async (input: SendRequestInput): Promise<SendRequestResult> => {
      if (input.method === 'OPTIONS') return res(204, '', {});
      const body = input.body ?? '';
      if (body.includes('"email"') && body.includes('"password"')) return res(200, { ok: true });
      return res(400, 'Bad Request'); // opaque error, no field names
    };

    const result = await findApiPayload({
      url: 'http://localhost:3000/api/auth/login',
      audit,
      transport,
      maxRounds: 4,
    });

    expect(result.succeeded).toBe(true);
    expect(result.requiredFields).toEqual(expect.arrayContaining(['email', 'password']));
  });
});
