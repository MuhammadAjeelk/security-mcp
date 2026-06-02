import { fetchPage } from './http-scanner.js';
import type {
  DiscoveredEndpoint,
  RoleProbeResult,
  TestAccount,
} from '../../types/scan.types.js';
import { AuditLogger } from '../logging/audit-logger.js';

const MAX_PROBES_PER_ROLE = 15;

/**
 * Re-fetch a curated subset of discovered endpoints once per test account so
 * downstream prompts can perform differential checks (IDOR/BOLA/BFLA/privilege
 * escalation). Read-only GETs only; no mutating verbs.
 */
export async function probeEndpointsPerRole(input: {
  endpoints: DiscoveredEndpoint[];
  accounts: TestAccount[];
  extraAllowedHosts?: string[];
  audit: AuditLogger;
}): Promise<Record<string, RoleProbeResult[]>> {
  const results: Record<string, RoleProbeResult[]> = {};
  if (input.accounts.length === 0) return results;

  const candidates = selectCandidates(input.endpoints);
  if (candidates.length === 0) return results;

  for (const account of input.accounts) {
    const perRole: RoleProbeResult[] = [];
    input.audit.event('probe.role.start', {
      role: account.role,
      candidateCount: candidates.length,
    });
    for (const endpoint of candidates) {
      try {
        const r = await fetchPage({
          url: endpoint.url,
          depth: 0,
          extraAllowedHosts: input.extraAllowedHosts,
          account,
          audit: input.audit,
        });
        perRole.push({
          url: endpoint.url,
          method: 'GET',
          status: r.page.status,
          contentType: r.headers['content-type'],
          bytes: r.page.bytes,
          redirected: r.page.redirected,
        });
      } catch (err) {
        perRole.push({
          url: endpoint.url,
          method: 'GET',
          status: 0,
          bytes: 0,
          redirected: false,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    results[account.role] = perRole;
    input.audit.event('probe.role.done', { role: account.role, results: perRole.length });
  }

  return results;
}

function selectCandidates(endpoints: DiscoveredEndpoint[]): DiscoveredEndpoint[] {
  const interesting = endpoints.filter((e) =>
    /\/(api|admin|account|users?|orders?|invoices?|tenants?|me|settings|billing|internal)\b/i.test(
      e.url,
    ),
  );
  const seen = new Set<string>();
  const out: DiscoveredEndpoint[] = [];
  for (const e of [...interesting, ...endpoints]) {
    if (seen.has(e.url)) continue;
    seen.add(e.url);
    out.push(e);
    if (out.length >= MAX_PROBES_PER_ROLE) break;
  }
  return out;
}
