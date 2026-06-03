import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetEnvCacheForTests } from '../config/env.js';

// Stub both network layers the discoverer uses.
const fetchPageMock = vi.fn();
const sendRequestMock = vi.fn();
vi.mock('../core/scanner/http-scanner.js', () => ({ fetchPage: (i: unknown) => fetchPageMock(i) }));
vi.mock('../core/scanner/http-request.js', () => ({ sendRequest: (i: unknown) => sendRequestMock(i) }));

import { discoverApiRoutes } from '../core/scanner/api-route-discovery.js';
import { AuditLogger } from '../core/logging/audit-logger.js';

const ORIGINAL = process.env;

function page(status: number, body = '') {
  return { page: { status, url: '', bytes: body.length, redirected: false, finalUrl: '', depth: 0 }, headers: {}, body, setCookies: [], truncated: false };
}

beforeEach(() => {
  process.env = { ...ORIGINAL, SCAN_API_DISCOVERY_MAX: '400' };
  resetEnvCacheForTests();
  fetchPageMock.mockReset();
  sendRequestMock.mockReset();
  sendRequestMock.mockResolvedValue({ status: 204, headers: {}, body: '', setCookies: [], durationMs: 1 });
});
afterEach(() => {
  process.env = ORIGINAL;
  resetEnvCacheForTests();
});

describe('discoverApiRoutes', () => {
  it('records undocumented routes that return 200 or 401/403 (gated), skips 404', () => {
    fetchPageMock.mockImplementation((input: { url: string }) => {
      const u = input.url;
      if (u.includes('/api/admins')) return Promise.resolve(page(403, 'forbidden'));
      if (u.includes('/api/users')) return Promise.resolve(page(200, '{"users":[]}'));
      return Promise.resolve(page(404, 'not found'));
    });
    return discoverApiRoutes({
      rootUrl: 'http://localhost:3000/',
      knownEndpoints: [{ url: 'http://localhost:3000/api/users/1', method: 'GET', source: 'api-spec' }],
      audit: new AuditLogger('t'),
      maxRequests: 1000,
    }).then((r) => {
      const urls = r.endpoints.map((e) => e.url);
      expect(urls.some((u) => u.endsWith('/api/admins'))).toBe(true); // 403 → exists, recorded
      expect(urls.some((u) => u.endsWith('/api/users'))).toBe(true); // 200 → recorded
      expect(r.notes.join(' ')).toMatch(/protected route .*admins.* 403/i);
      expect(r.endpoints.every((e) => e.source === 'api-discovery')).toBe(true);
    });
  });

  it('does not record a 404 sweep as routes', async () => {
    fetchPageMock.mockResolvedValue(page(404, 'nope'));
    const r = await discoverApiRoutes({
      rootUrl: 'http://localhost:3000/',
      knownEndpoints: [],
      audit: new AuditLogger('t'),
      maxRequests: 1000,
    });
    expect(r.endpoints).toEqual([]);
  });

  it('learns extra methods from the OPTIONS Allow header', async () => {
    fetchPageMock.mockImplementation((input: { url: string }) =>
      Promise.resolve(input.url.endsWith('/api/orders') ? page(200, 'ok') : page(404)),
    );
    sendRequestMock.mockResolvedValue({ status: 204, headers: { allow: 'GET, POST, DELETE' }, body: '', setCookies: [], durationMs: 1 });
    const r = await discoverApiRoutes({
      rootUrl: 'http://localhost:3000/',
      knownEndpoints: [{ url: 'http://localhost:3000/api/x', method: 'GET', source: 'crawler' }],
      audit: new AuditLogger('t'),
      maxRequests: 1000,
    });
    const orders = r.endpoints.filter((e) => e.url.endsWith('/api/orders'));
    const methods = orders.map((e) => e.method);
    expect(methods).toContain('POST');
    expect(methods).toContain('DELETE');
  });
});
