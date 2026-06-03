import { describe, expect, it } from 'vitest';
import { deriveFrontendCandidates, looksLikeApiHost } from '../core/scanner/frontend-hints.js';

describe('deriveFrontendCandidates', () => {
  it('strips the api. label and suggests app/www/parent origins', () => {
    const c = deriveFrontendCandidates('https://api.staging.lynsi.net/');
    expect(c).toContain('https://staging.lynsi.net');
    expect(c).toContain('https://app.staging.lynsi.net');
    expect(c).not.toContain('https://api.staging.lynsi.net'); // never the target itself
  });

  it('preserves http vs https', () => {
    const c = deriveFrontendCandidates('http://api.localtest.me/');
    expect(c.every((u) => u.startsWith('http://'))).toBe(true);
  });

  it('returns [] for a malformed URL', () => {
    expect(deriveFrontendCandidates('not a url')).toEqual([]);
  });
});

describe('looksLikeApiHost', () => {
  it('detects api hosts and /api paths', () => {
    expect(looksLikeApiHost('https://api.example.com/')).toBe(true);
    expect(looksLikeApiHost('https://example.com/api/v1')).toBe(true);
    expect(looksLikeApiHost('https://app.example.com/')).toBe(false);
  });
});
