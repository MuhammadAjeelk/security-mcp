import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { evaluateRedirect } from '../core/policy/redirect-policy.js';
import { resetEnvCacheForTests } from '../config/env.js';

const ORIGINAL = process.env;

beforeEach(() => {
  process.env = { ...ORIGINAL, ALLOWED_STAGING_HOSTS: 'staging.example.com' };
  resetEnvCacheForTests();
});

afterEach(() => {
  process.env = ORIGINAL;
  resetEnvCacheForTests();
});

describe('evaluateRedirect', () => {
  it('follows redirects within localhost', () => {
    const r = evaluateRedirect('http://localhost/', '/next');
    expect(r.follow).toBe(true);
  });

  it('blocks redirects to non-allowed hosts', () => {
    const r = evaluateRedirect('http://localhost/', 'https://example.com/leak');
    expect(r.follow).toBe(false);
  });

  it('follows redirect to allowlisted staging host', () => {
    const r = evaluateRedirect('http://localhost/', 'https://staging.example.com/done');
    expect(r.follow).toBe(true);
  });

  it('blocks redirect to a non-http(s) scheme', () => {
    const r = evaluateRedirect('http://localhost/', 'javascript:alert(1)');
    expect(r.follow).toBe(false);
  });
});
