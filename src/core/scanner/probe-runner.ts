import { request } from 'undici';
import { validateTarget } from '../policy/target-policy.js';
import { getEnv } from '../../config/env.js';
import { AuditLogger } from '../logging/audit-logger.js';
import { PROBE_LIBRARY, type ProbeDefinition, type ProbeOutcome } from './probe-library.js';
import type { Finding } from '../../types/finding.types.js';
import type { DiscoveredEndpoint, TestAccount } from '../../types/scan.types.js';

const MAX_PROBE_TARGETS = 10;
const MAX_PROBES_PER_TARGET = 4;

export interface ActiveProbeInput {
  endpoints: DiscoveredEndpoint[];
  account?: TestAccount;
  extraAllowedHosts?: string[];
  audit: AuditLogger;
}

/**
 * Run the active-but-safe probe library against a curated subset of endpoints.
 * Hard-capped to prevent any chance of abusive load.
 */
export async function runActiveProbes(input: ActiveProbeInput): Promise<Finding[]> {
  const env = getEnv();
  const targets = pickProbeTargets(input.endpoints);
  if (targets.length === 0) return [];

  input.audit.event('probes.start', { targets: targets.length, probes: PROBE_LIBRARY.length });

  const findings: Finding[] = [];
  for (const endpoint of targets) {
    const decision = validateTarget(endpoint.url, { extraAllowedHosts: input.extraAllowedHosts });
    if (!decision.allowed) {
      input.audit.event('probes.skip', { url: endpoint.url, reason: decision.reason });
      continue;
    }
    const targetProbes = pickProbesForEndpoint(endpoint);
    for (const probe of targetProbes) {
      try {
        const outcome = await issueProbe(endpoint.url, probe, input.account, env.SCAN_TIMEOUT_MS);
        const result = probe.detect(outcome);
        if (result.triggered) {
          findings.push(toFinding(endpoint.url, probe, outcome, result.evidence));
        }
      } catch (err) {
        input.audit.event('probes.error', {
          url: endpoint.url,
          probe: probe.id,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
  }

  input.audit.event('probes.done', { findings: findings.length });
  return findings;
}

function pickProbeTargets(endpoints: DiscoveredEndpoint[]): DiscoveredEndpoint[] {
  const candidates = endpoints.filter(
    (e) => /[?&]/.test(e.url) || /\/(api|search|filter|q|id)\b/i.test(e.url),
  );
  const seen = new Set<string>();
  const out: DiscoveredEndpoint[] = [];
  for (const e of [...candidates, ...endpoints]) {
    if (seen.has(e.url)) continue;
    seen.add(e.url);
    out.push(e);
    if (out.length >= MAX_PROBE_TARGETS) break;
  }
  return out;
}

function pickProbesForEndpoint(endpoint: DiscoveredEndpoint): ProbeDefinition[] {
  const hasQuery = /[?&]/.test(endpoint.url);
  const probes = PROBE_LIBRARY.filter((p) => {
    if (p.category === 'open-redirect' && !/\b(redirect|next|return_to|url|target)\b/i.test(endpoint.url)) {
      return false;
    }
    if (!hasQuery && (p.category === 'sql-injection' || p.category === 'xss-reflected')) {
      return false;
    }
    return true;
  });
  return probes.slice(0, MAX_PROBES_PER_TARGET);
}

async function issueProbe(
  url: string,
  probe: ProbeDefinition,
  account: TestAccount | undefined,
  timeoutMs: number,
): Promise<ProbeOutcome> {
  const target = injectPayload(url, probe);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const start = Date.now();
  try {
    const headers: Record<string, string> = {
      'user-agent': 'security-mcp/0.2 (+authorized-testing-only)',
    };
    if (account?.token) headers['authorization'] = `Bearer ${account.token}`;
    if (probe.payload.headerName && probe.payload.headerValue) {
      headers[probe.payload.headerName] = probe.payload.headerValue;
    }
    const response = await request(target, {
      method: 'GET',
      headers,
      signal: controller.signal,
      maxRedirections: 0,
    });
    const body = await response.body.text();
    const responseHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(response.headers)) {
      if (v === undefined) continue;
      responseHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
    }
    return {
      status: response.statusCode,
      headers: responseHeaders,
      body: body.slice(0, 64 * 1024),
      durationMs: Date.now() - start,
    };
  } finally {
    clearTimeout(timer);
  }
}

function injectPayload(url: string, probe: ProbeDefinition): string {
  if (probe.payload.value === '' || probe.payload.headerName) return url;
  try {
    const u = new URL(url);
    if (u.searchParams.size > 0) {
      const firstKey = [...u.searchParams.keys()][0]!;
      u.searchParams.set(firstKey, probe.payload.value);
    } else {
      u.searchParams.set('q', probe.payload.value);
    }
    return u.toString();
  } catch {
    return url;
  }
}

function toFinding(
  url: string,
  probe: ProbeDefinition,
  outcome: ProbeOutcome,
  detection: Record<string, unknown>,
): Finding {
  return {
    id: `probe.${probe.id}.${shortHash(url)}`,
    title: `Active probe confirmed: ${probe.id}`,
    severity: probe.severityOnConfirm,
    category: probe.category,
    description: `Probe \`${probe.id}\` triggered on ${url}. ${probe.description}`,
    evidence: {
      url,
      status: outcome.status,
      durationMs: outcome.durationMs,
      detection,
    },
    impact: severityImpact(probe),
    remediation:
      'Manually verify, then apply the appropriate fix (parameterised queries, contextual encoding, ' +
      'allowlists, output validation). Add a regression test that replays the same probe payload.',
    confidence: probe.confidenceOnConfirm,
    promptId: `active.${probe.id}`,
  };
}

function severityImpact(probe: ProbeDefinition): string {
  switch (probe.category) {
    case 'sql-injection':
    case 'command-injection':
      return 'Full database / host compromise if confirmed.';
    case 'xss-reflected':
      return 'Session hijack / account takeover via JavaScript in victim browsers.';
    case 'open-redirect':
      return 'Phishing pivot; OAuth flow hijack.';
    case 'crlf-injection':
    case 'header-injection':
      return 'Response splitting, cache poisoning, session fixation.';
    case 'path-traversal':
      return 'Read of arbitrary local files.';
    case 'ssrf-marker':
      return 'Pivot into internal services / cloud metadata.';
    case 'time-based-blind':
      return 'Latency anomaly — investigate for blind injection.';
  }
}

function shortHash(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
}
