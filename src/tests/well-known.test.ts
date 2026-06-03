import { describe, expect, it } from 'vitest';
import { parseOpenApiEndpoints, WELL_KNOWN_PATHS } from '../core/scanner/well-known.js';

const ORIGIN = 'http://localhost:3000';

describe('parseOpenApiEndpoints', () => {
  it('extracts operations from an OpenAPI 3 spec, resolving servers[].url', () => {
    const spec = JSON.stringify({
      openapi: '3.0.0',
      servers: [{ url: '/api/v1' }],
      paths: {
        '/users': { get: {}, post: {} },
        '/users/{id}': { get: {}, delete: {} },
      },
    });
    const eps = parseOpenApiEndpoints(spec, ORIGIN);
    const keys = eps.map((e) => `${e.method} ${e.url}`);
    expect(keys).toContain('GET http://localhost:3000/api/v1/users');
    expect(keys).toContain('POST http://localhost:3000/api/v1/users');
    expect(keys).toContain('DELETE http://localhost:3000/api/v1/users/{id}');
    expect(eps.every((e) => e.source === 'api-spec')).toBe(true);
  });

  it('resolves Swagger 2 basePath', () => {
    const spec = JSON.stringify({
      swagger: '2.0',
      basePath: '/v2',
      paths: { '/pets': { get: {} } },
    });
    const eps = parseOpenApiEndpoints(spec, ORIGIN);
    expect(eps).toEqual([
      { url: 'http://localhost:3000/v2/pets', method: 'GET', source: 'api-spec' },
    ]);
  });

  it('falls back to GET when a path declares no recognized methods', () => {
    const spec = JSON.stringify({ openapi: '3.0.0', paths: { '/ping': { parameters: [] } } });
    const eps = parseOpenApiEndpoints(spec, ORIGIN);
    expect(eps).toEqual([
      { url: 'http://localhost:3000/ping', method: 'GET', source: 'api-spec' },
    ]);
  });

  it('ignores absolute servers pointing off-origin', () => {
    const spec = JSON.stringify({
      openapi: '3.0.0',
      servers: [{ url: 'https://other.example.com/api' }],
      paths: { '/x': { get: {} } },
    });
    const eps = parseOpenApiEndpoints(spec, ORIGIN);
    expect(eps[0]!.url).toBe('http://localhost:3000/x');
  });

  it('returns [] for non-JSON or specs without a paths object', () => {
    expect(parseOpenApiEndpoints('not json', ORIGIN)).toEqual([]);
    expect(parseOpenApiEndpoints('{}', ORIGIN)).toEqual([]);
    expect(parseOpenApiEndpoints(JSON.stringify({ paths: 'nope' }), ORIGIN)).toEqual([]);
  });

  it('includes /api/docs among the well-known paths', () => {
    expect(WELL_KNOWN_PATHS).toContain('/api/docs');
  });
});
