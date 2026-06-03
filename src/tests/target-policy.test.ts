import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { validateTarget } from '../core/policy/target-policy.js';
import { resetEnvCacheForTests } from '../config/env.js';

const ORIGINAL = process.env;

beforeEach(() => {
  process.env = { ...ORIGINAL, ALLOWED_STAGING_HOSTS: 'staging.example.com,dev.example.com' };
  resetEnvCacheForTests();
});

afterEach(() => {
  process.env = ORIGINAL;
  resetEnvCacheForTests();
});

describe('validateTarget', () => {
  it('allows localhost', () => {
    expect(validateTarget('http://localhost:3000/').allowed).toBe(true);
    expect(validateTarget('http://127.0.0.1/').allowed).toBe(true);
    expect(validateTarget('http://[::1]:8080/').allowed).toBe(true);
  });

  it('allows configured staging host', () => {
    expect(validateTarget('https://staging.example.com/api').allowed).toBe(true);
    expect(validateTarget('https://dev.example.com/').allowed).toBe(true);
  });

  it('allows any hostname containing "staging" without an explicit allowlist entry', () => {
    const r = validateTarget('https://api.staging.lynsi.net/');
    expect(r.allowed).toBe(true);
    expect(r.classification).toBe('staging');
    expect(validateTarget('https://web.staging.anything.io/').allowed).toBe(true);
    expect(validateTarget('https://mystaging.dev/').allowed).toBe(true);
  });

  it('still blocks a staging host that also looks production-flavored', () => {
    // forbidden substrings beat the broad "staging" substring allow
    expect(validateTarget('https://staging-prod.example.com/').allowed).toBe(false);
    expect(validateTarget('https://staging.live.example.com/').allowed).toBe(false);
  });

  it('lets an explicit allowlist entry override forbidden substrings', () => {
    process.env.ALLOWED_STAGING_HOSTS = 'staging.live.example.com';
    resetEnvCacheForTests();
    const r = validateTarget('https://staging.live.example.com/');
    expect(r.allowed).toBe(true);
    expect(r.classification).toBe('staging');
    // a per-call extra host works the same way
    expect(
      validateTarget('https://app.live.example.com/', {
        extraAllowedHosts: ['app.live.example.com'],
      }).allowed,
    ).toBe(true);
    // but a non-listed prod/live host is still blocked
    expect(validateTarget('https://other.live.example.com/').allowed).toBe(false);
  });

  it('honours extraAllowedHosts on a per-call basis', () => {
    expect(validateTarget('https://qa.example.com/').allowed).toBe(false);
    expect(
      validateTarget('https://qa.example.com/', { extraAllowedHosts: ['qa.example.com'] }).allowed,
    ).toBe(true);
  });

  it('blocks production-flavored hostnames', () => {
    expect(validateTarget('https://api.production.example.com/').allowed).toBe(false);
    expect(validateTarget('https://app.live.example.com/').allowed).toBe(false);
    expect(validateTarget('https://prod.example.com/').allowed).toBe(false);
  });

  it('blocks cloud metadata IP', () => {
    const r = validateTarget('http://169.254.169.254/latest/meta-data/');
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/blocklist/);
  });

  it('blocks private network without explicit allowlist', () => {
    expect(validateTarget('http://10.0.0.5/').allowed).toBe(false);
    expect(validateTarget('http://192.168.1.20/').allowed).toBe(false);
  });

  it('rejects non-http(s) protocols', () => {
    expect(validateTarget('file:///etc/passwd').allowed).toBe(false);
    expect(validateTarget('ftp://localhost/').allowed).toBe(false);
  });

  it('rejects malformed URLs', () => {
    expect(validateTarget('not a url').allowed).toBe(false);
    expect(validateTarget('').allowed).toBe(false);
  });

  it('rejects unknown public hostnames', () => {
    expect(validateTarget('https://example.com/').allowed).toBe(false);
    expect(validateTarget('https://google.com/').allowed).toBe(false);
  });
});
