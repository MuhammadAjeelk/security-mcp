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
});
