import { describe, expect, it } from 'vitest';
import { buildAttackSurface } from '../core/scanner/attack-surface.js';
import type { ScanEvidence } from '../types/scan.types.js';

function baseEvidence(overrides: Partial<ScanEvidence> = {}): ScanEvidence {
  return {
    targetUrl: 'http://localhost:3000/',
    scanType: 'deep',
    startedAt: '2026-01-01T00:00:00.000Z',
    completedAt: '2026-01-01T00:01:00.000Z',
    requestCount: 5,
    pages: [],
    headers: {},
    cookies: {},
    forms: [],
    endpoints: [],
    notes: [],
    ...overrides,
  };
}

describe('buildAttackSurface', () => {
  it('derives per-endpoint flags deterministically', () => {
    const ev = baseEvidence({
      endpoints: [
        { url: 'http://localhost:3000/api/users/42', method: 'GET', source: 'crawler' },
        { url: 'http://localhost:3000/search?q=hi', method: 'GET', source: 'link' },
        { url: 'http://localhost:3000/admin/panel', method: 'GET', source: 'link' },
        { url: 'http://localhost:3000/static', method: 'GET', source: 'crawler' },
      ],
    });
    const s = buildAttackSurface(ev);

    expect(s.totalEndpoints).toBe(4);
    const byId = s.endpoints.find((e) => e.url.endsWith('/users/42'))!;
    expect(byId.hasPathId).toBe(true);
    const search = s.endpoints.find((e) => e.url.includes('?q='))!;
    expect(search.hasQueryParams).toBe(true);
    const admin = s.endpoints.find((e) => e.url.includes('/admin'))!;
    expect(admin.looksAdmin).toBe(true);
  });

  it('marks endpoints auth-gated when role probes disagree or return 401/403', () => {
    const ev = baseEvidence({
      endpoints: [{ url: 'http://localhost:3000/account', method: 'GET', source: 'crawler' }],
      roleProbes: {
        admin: [{ url: 'http://localhost:3000/account', method: 'GET', status: 200, bytes: 10, redirected: false }],
        anon: [{ url: 'http://localhost:3000/account', method: 'GET', status: 403, bytes: 0, redirected: false }],
      },
    });
    const s = buildAttackSurface(ev);
    expect(s.endpoints[0]!.authGated).toBe(true);
    expect(s.authGated).toBe(1);
  });

  it('flags upload forms and maps them to file goals', () => {
    const ev = baseEvidence({
      endpoints: [{ url: 'http://localhost:3000/upload', method: 'POST', source: 'crawler' }],
      forms: [
        {
          pageUrl: 'http://localhost:3000/profile',
          action: 'http://localhost:3000/upload',
          method: 'POST',
          fields: ['avatar', 'csrf'],
        },
      ],
    });
    const s = buildAttackSurface(ev);
    const up = s.endpoints[0]!;
    expect(up.hasForm).toBe(true);
    expect(up.isUpload).toBe(true);
    expect(up.applicableGoals.some((g) => g.startsWith('files.'))).toBe(true);
  });

  it('always includes a goal catalog mirroring the prompt registry', () => {
    const s = buildAttackSurface(baseEvidence());
    expect(s.goalCatalog.length).toBeGreaterThan(30);
    expect(s.goalCatalog[0]).toHaveProperty('id');
    expect(s.goalCatalog[0]).toHaveProperty('category');
  });
});
