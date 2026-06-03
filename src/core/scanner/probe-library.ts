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

export type ProbeCategory =
  | 'sql-injection'
  | 'xss-reflected'
  | 'open-redirect'
  | 'crlf-injection'
  | 'header-injection'
  | 'path-traversal'
  | 'ssrf-marker'
  | 'command-injection'
  | 'time-based-blind'
  | 'ssti'
  | 'xxe'
  | 'graphql-introspection'
  | 'nosql-operator'
  | 'cors-misconfig'
  | 'host-header-injection';

/** How the probe runner should deliver this probe. */
export interface ProbeRequestSpec {
  method: string;
  contentType?: string;
  /** Raw request body (for POST/PUT body probes). */
  body?: string;
}

export interface ProbeDefinition {
  id: string;
  /** Vulnerability class this probe is testing for. */
  category: ProbeCategory;
  description: string;
  payload: ProbePayload;
  /** Severity to emit when the probe is confirmed (not exploited). */
  severityOnConfirm: Severity;
  /** Confidence to report on confirmation. */
  confidenceOnConfirm: Confidence;
  /**
   * Delivery mode. 'query' (default) injects payload.value into a query param.
   * 'header' sets payload.headerName/headerValue. 'body' sends `request`.
   */
  mode?: 'query' | 'header' | 'body';
  /** For mode 'body': the request to send (method/content-type/body). */
  request?: ProbeRequestSpec;
  /**
   * Restrict this probe to endpoint URLs matching this pattern (e.g. only run
   * GraphQL introspection against /graphql). Omit to apply broadly.
   */
  appliesTo?: RegExp;
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
      // A DNS/connection error naming the canary means the server actually
      // tried to FETCH it — that is the SSRF signal. Mere reflection of the
      // canary (apps that echo the request URL in a 404/400 body) is NOT SSRF,
      // so we require a fetch-failure signature, not bare reflection.
      const fetchError =
        /(getaddrinfo|ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ETIMEDOUT|dns lookup|failed to fetch|fetch failed|request to .*smcp-ssrf-canary|unable to (resolve|connect))/i;
      const canaryNearError =
        /smcp-ssrf-canary\.invalid/.test(r.body) && fetchError.test(r.body);
      if (canaryNearError || /getaddrinfo|EAI_AGAIN|ENOTFOUND/i.test(r.body)) {
        return {
          triggered: true,
          evidence: { hint: 'server attempted to resolve/fetch the canary host (SSRF)' },
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
  {
    id: 'ssti.arithmetic-marker',
    category: 'ssti',
    description:
      'Server-side template injection canary. Sends a guarded arithmetic expression in common ' +
      'template syntaxes; if the server renders the math (49), a template engine is evaluating input.',
    payload: { value: 'smcp{{7*7}}${7*7}#{7*7}<%=7*7%>' },
    severityOnConfirm: 'critical',
    confidenceOnConfirm: 'medium',
    detect: (r) => {
      // The literal payload must NOT remain verbatim; the evaluated form (smcp49) is the tell.
      if (/smcp49\b/.test(r.body) && !/smcp\{\{7\*7\}\}/.test(r.body)) {
        return { triggered: true, evidence: { hint: 'template expression evaluated (7*7 → 49)' } };
      }
      return { triggered: false, evidence: {} };
    },
  },
  {
    id: 'host-header.injection',
    category: 'host-header-injection',
    description:
      'Sets a spoofed X-Forwarded-Host. If the value is reflected into links, redirects, or the ' +
      'body, the app trusts attacker-controlled host headers (password-reset poisoning, cache issues).',
    mode: 'header',
    payload: { value: '', headerName: 'x-forwarded-host', headerValue: 'smcp-evil.invalid' },
    severityOnConfirm: 'medium',
    confidenceOnConfirm: 'medium',
    detect: (r) => {
      const loc = r.headers['location'] ?? '';
      if (/smcp-evil\.invalid/.test(loc) || /smcp-evil\.invalid/.test(r.body)) {
        return {
          triggered: true,
          evidence: { hint: 'spoofed X-Forwarded-Host reflected', location: loc || undefined },
        };
      }
      return { triggered: false, evidence: {} };
    },
  },
  {
    id: 'cors.origin-reflection',
    category: 'cors-misconfig',
    description:
      'Sends a foreign Origin and checks whether the server reflects it in ' +
      'Access-Control-Allow-Origin while allowing credentials — a cross-origin data-theft misconfig.',
    mode: 'header',
    payload: { value: '', headerName: 'origin', headerValue: 'https://smcp-evil.invalid' },
    severityOnConfirm: 'high',
    confidenceOnConfirm: 'high',
    detect: (r) => {
      const acao = r.headers['access-control-allow-origin'] ?? '';
      const acac = r.headers['access-control-allow-credentials'] ?? '';
      const reflected = acao === 'https://smcp-evil.invalid';
      const wildcardCreds = acao === '*' && /true/i.test(acac);
      if ((reflected && /true/i.test(acac)) || reflected || wildcardCreds) {
        return {
          triggered: true,
          evidence: {
            'access-control-allow-origin': acao,
            'access-control-allow-credentials': acac || undefined,
            hint: wildcardCreds
              ? 'wildcard ACAO with credentials'
              : 'foreign Origin reflected in ACAO',
          },
        };
      }
      return { triggered: false, evidence: {} };
    },
  },
  {
    id: 'graphql.introspection-enabled',
    category: 'graphql-introspection',
    description:
      'Sends a minimal introspection query to a GraphQL endpoint. A populated __schema means ' +
      'introspection is enabled in production — it hands an attacker the full API map.',
    mode: 'body',
    appliesTo: /graphql/i,
    payload: { value: '' },
    request: {
      method: 'POST',
      contentType: 'application/json',
      body: JSON.stringify({ query: '{__schema{queryType{name} types{name}}}' }),
    },
    severityOnConfirm: 'medium',
    confidenceOnConfirm: 'high',
    detect: (r) => {
      if (/"__schema"\s*:/.test(r.body) && /"types"\s*:/.test(r.body)) {
        return { triggered: true, evidence: { hint: 'GraphQL introspection returned a schema' } };
      }
      return { triggered: false, evidence: {} };
    },
  },
  {
    id: 'nosql.operator-injection',
    category: 'nosql-operator',
    description:
      'Sends a JSON body using a Mongo-style operator object ({"$gt":""}) in place of a string. ' +
      'A different response vs a normal value suggests the operator reached the database layer.',
    mode: 'body',
    appliesTo: /login|auth|search|user|query|find/i,
    payload: { value: '' },
    request: {
      method: 'POST',
      contentType: 'application/json',
      body: JSON.stringify({ username: { $gt: '' }, password: { $gt: '' } }),
    },
    severityOnConfirm: 'high',
    confidenceOnConfirm: 'low',
    detect: (r) => {
      // Auth bypass tell: operator object accepted (2xx) where a string login would 401,
      // or a Mongo/cast error surfaced.
      if (/CastError|MongoError|\$gt|BSON|cannot be cast/i.test(r.body)) {
        return { triggered: true, evidence: { hint: 'NoSQL operator reached the data layer (error)' } };
      }
      if (r.status >= 200 && r.status < 300 && /token|session|"id"|success/i.test(r.body)) {
        return {
          triggered: true,
          evidence: { hint: 'operator-object body accepted with a success-shaped response — verify auth bypass' },
        };
      }
      return { triggered: false, evidence: {} };
    },
  },
  {
    id: 'xxe.entity-canary',
    category: 'xxe',
    description:
      'Posts an XML document declaring a benign internal entity (no external/SYSTEM fetch). If the ' +
      'entity is expanded in the response, the parser resolves entities and is likely XXE-prone.',
    mode: 'body',
    appliesTo: /xml|soap|upload|import|feed/i,
    payload: { value: '' },
    request: {
      method: 'POST',
      contentType: 'application/xml',
      body:
        '<?xml version="1.0"?><!DOCTYPE smcp [<!ENTITY smcpx "SMCP_XXE_CANARY">]>' +
        '<smcp><v>&smcpx;</v></smcp>',
    },
    severityOnConfirm: 'high',
    confidenceOnConfirm: 'low',
    detect: (r) => {
      if (/SMCP_XXE_CANARY/.test(r.body)) {
        return { triggered: true, evidence: { hint: 'internal XML entity was expanded in the response' } };
      }
      return { triggered: false, evidence: {} };
    },
  },
]);

export function probesByCategory(cat: ProbeDefinition['category']): ProbeDefinition[] {
  return PROBE_LIBRARY.filter((p) => p.category === cat);
}
