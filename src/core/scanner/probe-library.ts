import type { Confidence, Severity } from '../../types/finding.types.js';

export interface ProbePayload {
  /** Value to inject into the chosen parameter. */
  value: string;
  /** Optional separate header to set (instead of/in addition to query/body injection). */
  headerName?: string;
  headerValue?: string;
}

export interface ProbeOutcome {
  status: number;
  headers: Record<string, string>;
  body: string;
  durationMs: number;
}

export interface ProbeDetection {
  triggered: boolean;
  evidence: Record<string, unknown>;
}

export interface ProbeDefinition {
  id: string;
  /** Vulnerability class this probe is testing for. */
  category:
    | 'sql-injection'
    | 'xss-reflected'
    | 'open-redirect'
    | 'crlf-injection'
    | 'header-injection'
    | 'path-traversal'
    | 'ssrf-marker'
    | 'command-injection'
    | 'time-based-blind';
  description: string;
  payload: ProbePayload;
  /** Severity to emit when the probe is confirmed (not exploited). */
  severityOnConfirm: Severity;
  /** Confidence to report on confirmation. */
  confidenceOnConfirm: Confidence;
  /**
   * Inspect the response and decide whether the probe was confirmed.
   *
   * MUST NOT mutate state. MUST NOT issue secondary requests. Detection is
   * based solely on the response shape passed in.
   */
  detect(outcome: ProbeOutcome): ProbeDetection;
}

const SQL_ERROR_RE =
  /(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite\/JDBCDriver|sqlite3\.OperationalError|unclosed quotation mark|psycopg2)/i;

const STACK_TRACE_RE = /(Traceback \(most recent call last\)|at [\w$.]+\(.*\.java:\d+\)|^\s+at .*\(.*\.(js|ts):\d+:\d+\)$)/m;

/**
 * Library of safe, non-exploitative probes. Every probe is designed to elicit
 * a *signal* that a vulnerability exists without delivering a working exploit.
 */
export const PROBE_LIBRARY: readonly ProbeDefinition[] = Object.freeze([
  {
    id: 'sqli.single-quote-marker',
    category: 'sql-injection',
    description: 'Single quote marker — looks for SQL parser error reflection without UNION/DROP.',
    payload: { value: "'__smcp_sqli__" },
    severityOnConfirm: 'high',
    confidenceOnConfirm: 'medium',
    detect: (r) => {
      if (SQL_ERROR_RE.test(r.body)) {
        return { triggered: true, evidence: { matched: 'sql error signature in response' } };
      }
      return { triggered: false, evidence: {} };
    },
  },
  {
    id: 'sqli.time-based-marker',
    category: 'time-based-blind',
    description: 'Detects unusually long response times after a benign marker is added. NO SLEEP() injection.',
    payload: { value: '__smcp_time__' },
    severityOnConfirm: 'medium',
    confidenceOnConfirm: 'low',
    detect: (r) => {
      if (r.durationMs > 5000) {
        return {
          triggered: true,
          evidence: { durationMs: r.durationMs, hint: 'unusual latency — investigate manually' },
        };
      }
      return { triggered: false, evidence: {} };
    },
  },
  {
    id: 'xss.reflected-marker',
    category: 'xss-reflected',
    description: 'Benign uppercase marker — checks whether it appears in the response body unencoded.',
    payload: { value: '__SMCP_XSS_MARKER__' },
    severityOnConfirm: 'high',
    confidenceOnConfirm: 'medium',
    detect: (r) => {
      if (r.body.includes('__SMCP_XSS_MARKER__')) {
        const encoded = r.body.includes('__SMCP_XSS_MARKER__&') || r.body.includes('&#');
        return {
          triggered: true,
          evidence: {
            reflected: true,
            appearsEncoded: encoded,
            hint: encoded
              ? 'marker reflected but appears encoded — verify context'
              : 'marker reflected verbatim — context-encoding likely missing',
          },
        };
      }
      return { triggered: false, evidence: {} };
    },
  },
  {
    id: 'open-redirect.scheme-relative',
    category: 'open-redirect',
    description: 'Scheme-relative URL pointing to a host on the same allowlist — checks for redirect honoring.',
    payload: { value: '//localhost.smcp.invalid/' },
    severityOnConfirm: 'medium',
    confidenceOnConfirm: 'medium',
    detect: (r) => {
      const loc = r.headers['location'];
      if (r.status >= 300 && r.status < 400 && loc && /smcp\.invalid/.test(loc)) {
        return { triggered: true, evidence: { location: loc } };
      }
      return { triggered: false, evidence: {} };
    },
  },
  {
    id: 'crlf.header-injection',
    category: 'crlf-injection',
    description: 'CRLF in a header value — checks whether the server splits the response.',
    payload: { value: 'foo', headerName: 'x-smcp-probe', headerValue: 'a\r\nX-Smcp-Injected: yes' },
    severityOnConfirm: 'high',
    confidenceOnConfirm: 'high',
    detect: (r) => {
      if (r.headers['x-smcp-injected']) {
        return {
          triggered: true,
          evidence: { injectedHeaderEchoed: r.headers['x-smcp-injected'] },
        };
      }
      return { triggered: false, evidence: {} };
    },
  },
  {
    id: 'path-traversal.canary',
    category: 'path-traversal',
    description: 'Dot-dot canary that does NOT escape the web root — looks for suspicious behavior.',
    payload: { value: '..%2F..%2F__smcp_canary__' },
    severityOnConfirm: 'high',
    confidenceOnConfirm: 'low',
    detect: (r) => {
      if (STACK_TRACE_RE.test(r.body) || /no such file/i.test(r.body)) {
        return {
          triggered: true,
          evidence: { hint: 'path-traversal canary triggered fs-related error/stack trace' },
        };
      }
      return { triggered: false, evidence: {} };
    },
  },
  {
    id: 'ssrf.invalid-marker',
    category: 'ssrf-marker',
    description: 'A clearly-invalid URL that should never be fetched — looks for DNS/error reflection.',
    payload: { value: 'http://smcp-ssrf-canary.invalid/' },
    severityOnConfirm: 'high',
    confidenceOnConfirm: 'low',
    detect: (r) => {
      if (/smcp-ssrf-canary\.invalid|getaddrinfo/i.test(r.body)) {
        return {
          triggered: true,
          evidence: { hint: 'canary host name reflected in response — likely SSRF attempt visible' },
        };
      }
      return { triggered: false, evidence: {} };
    },
  },
  {
    id: 'command-injection.echo-canary',
    category: 'command-injection',
    description: "Benign canary using only safe characters; never includes shell metacharacters.",
    payload: { value: '__smcp_cmd_canary__' },
    severityOnConfirm: 'critical',
    confidenceOnConfirm: 'low',
    detect: (r) => {
      if (/bin\/(sh|bash)|sh: \d+:|command not found/i.test(r.body)) {
        return {
          triggered: true,
          evidence: { hint: 'shell-related error visible in response body' },
        };
      }
      return { triggered: false, evidence: {} };
    },
  },
]);

export function probesByCategory(cat: ProbeDefinition['category']): ProbeDefinition[] {
  return PROBE_LIBRARY.filter((p) => p.category === cat);
}
