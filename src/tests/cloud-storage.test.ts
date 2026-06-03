import { describe, expect, it } from 'vitest';
import { cloudStoragePrompt } from '../core/prompt-engine/prompts/infrastructure/cloud-storage.prompt.js';
import type { ScanEvidence } from '../types/scan.types.js';

function evidence(overrides: Partial<ScanEvidence> = {}): ScanEvidence {
  return {
    targetUrl: 'http://localhost:3000/',
    scanType: 'deep',
    startedAt: '2026-01-01T00:00:00.000Z',
    completedAt: '2026-01-01T00:01:00.000Z',
    requestCount: 1,
    pages: [],
    headers: {},
    cookies: {},
    forms: [],
    endpoints: [],
    notes: [],
    ...overrides,
  };
}

function run(ev: ScanEvidence) {
  // PromptContext shape: the heuristic only reads ctx.evidence.
  return cloudStoragePrompt.heuristic!({ evidence: ev } as never);
}

describe('cloudStoragePrompt heuristic', () => {
  it('flags an S3 bucket URL disclosed in a discovered endpoint', () => {
    const f = run(
      evidence({
        endpoints: [
          { url: 'https://my-app-uploads.s3.us-east-1.amazonaws.com/u/1.jpg', method: 'GET', source: 'api-spec' },
        ],
      }),
    );
    expect(f.length).toBeGreaterThan(0);
    expect(f[0]!.title).toMatch(/Cloud storage reference disclosed/);
    expect(f[0]!.category).toBe('infrastructure');
  });

  it('flags a leaked AWS presigned URL as high severity', () => {
    const f = run(
      evidence({
        notes: [
          'redirect Location: https://b.s3.amazonaws.com/k?X-Amz-Signature=abc123&X-Amz-Expires=604800',
        ],
      }),
    );
    const presigned = f.find((x) => /presigned/i.test(x.title));
    expect(presigned).toBeDefined();
    expect(presigned!.severity).toBe('high');
  });

  it('detects storage hosts surfaced in response headers (redirects)', () => {
    const f = run(
      evidence({
        headers: {
          'https://localhost:3000/avatar': {
            location: 'https://assets.storage.googleapis.com/avatars/9.png',
          },
        },
      }),
    );
    expect(f.some((x) => /Google Cloud Storage|GCS/.test(x.title))).toBe(true);
  });

  it('returns nothing when no storage references are present', () => {
    expect(run(evidence({ endpoints: [{ url: 'https://localhost:3000/api/health', method: 'GET', source: 'crawler' }] }))).toEqual([]);
  });
});
