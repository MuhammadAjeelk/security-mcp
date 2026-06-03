import { describe, expect, it } from 'vitest';
import { PROBE_LIBRARY } from '../core/scanner/probe-library.js';

describe('PROBE_LIBRARY', () => {
  it('all probes have id, category, payload, detect()', () => {
    expect(PROBE_LIBRARY.length).toBeGreaterThan(5);
    for (const p of PROBE_LIBRARY) {
      expect(typeof p.id).toBe('string');
      expect(typeof p.category).toBe('string');
      expect(typeof p.payload).toBe('object');
      expect(typeof p.detect).toBe('function');
    }
  });

  it('SQL injection probe detects sqlite error', () => {
    const sqli = PROBE_LIBRARY.find((p) => p.id === 'sqli.single-quote-marker')!;
    const triggered = sqli.detect({
      status: 500,
      headers: {},
      body: 'sqlite3.OperationalError: near "smcp": syntax error',
      durationMs: 30,
    });
    expect(triggered.triggered).toBe(true);
  });

  it('SQL injection probe is quiet on a clean 200', () => {
    const sqli = PROBE_LIBRARY.find((p) => p.id === 'sqli.single-quote-marker')!;
    const triggered = sqli.detect({
      status: 200,
      headers: {},
      body: '<html><h1>welcome</h1></html>',
      durationMs: 10,
    });
    expect(triggered.triggered).toBe(false);
  });

  it('XSS marker probe fires when marker reflected unencoded', () => {
    const xss = PROBE_LIBRARY.find((p) => p.id === 'xss.reflected-marker')!;
    const r = xss.detect({
      status: 200,
      headers: {},
      body: 'You searched for __SMCP_XSS_MARKER__',
      durationMs: 5,
    });
    expect(r.triggered).toBe(true);
  });

  it('CRLF probe detects echoed injected header', () => {
    const crlf = PROBE_LIBRARY.find((p) => p.id === 'crlf.header-injection')!;
    const r = crlf.detect({
      status: 200,
      headers: { 'x-smcp-injected': 'yes' },
      body: '',
      durationMs: 5,
    });
    expect(r.triggered).toBe(true);
  });

  it('SSTI probe fires only when the expression evaluates (49), not when echoed verbatim', () => {
    const ssti = PROBE_LIBRARY.find((p) => p.id === 'ssti.arithmetic-marker')!;
    expect(ssti.detect({ status: 200, headers: {}, body: 'result: smcp49', durationMs: 1 }).triggered).toBe(true);
    expect(
      ssti.detect({ status: 200, headers: {}, body: 'echo: smcp{{7*7}}${7*7}', durationMs: 1 }).triggered,
    ).toBe(false);
  });

  it('CORS probe fires on reflected foreign Origin with credentials', () => {
    const cors = PROBE_LIBRARY.find((p) => p.id === 'cors.origin-reflection')!;
    const r = cors.detect({
      status: 200,
      headers: {
        'access-control-allow-origin': 'https://smcp-evil.invalid',
        'access-control-allow-credentials': 'true',
      },
      body: '',
      durationMs: 1,
    });
    expect(r.triggered).toBe(true);
  });

  it('GraphQL introspection probe fires when a schema is returned', () => {
    const gql = PROBE_LIBRARY.find((p) => p.id === 'graphql.introspection-enabled')!;
    const r = gql.detect({
      status: 200,
      headers: {},
      body: '{"data":{"__schema":{"types":[{"name":"User"}]}}}',
      durationMs: 1,
    });
    expect(r.triggered).toBe(true);
    expect(gql.mode).toBe('body');
    expect(gql.appliesTo?.test('http://x/graphql')).toBe(true);
  });

  it('XXE probe fires when the internal entity is expanded', () => {
    const xxe = PROBE_LIBRARY.find((p) => p.id === 'xxe.entity-canary')!;
    expect(
      xxe.detect({ status: 200, headers: {}, body: '<v>SMCP_XXE_CANARY</v>', durationMs: 1 }).triggered,
    ).toBe(true);
  });

  it('host-header probe fires when spoofed host is reflected in Location', () => {
    const hh = PROBE_LIBRARY.find((p) => p.id === 'host-header.injection')!;
    const r = hh.detect({
      status: 302,
      headers: { location: 'http://smcp-evil.invalid/reset?token=x' },
      body: '',
      durationMs: 1,
    });
    expect(r.triggered).toBe(true);
  });
});
