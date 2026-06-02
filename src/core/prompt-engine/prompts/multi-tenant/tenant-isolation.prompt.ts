import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence } from '../../helpers.js';

export const tenantIsolationPrompt: SecurityPrompt = {
  id: 'multi-tenant.isolation',
  title: 'Multi-tenant data isolation',
  category: 'multi-tenant',
  severityFocus: 'critical',
  prompt: [
    'Goal: Verify tenant scoping is enforced server-side (not client-side via tenant_id query).',
    'Detect responses where data from one tenant could be accessed by another principal.',
    '',
    'Evidence required: at least two test accounts in different tenants; identical endpoint',
    'fetched by each; differential response codes and approximate body sizes.',
    '',
    'Constraints: never mutate cross-tenant data; read-only differential test.',
    '',
    'Output: severity critical when foreign tenant receives 2xx with data; confidence high only',
    'when the differential probe was executed.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    if (ctx.testAccounts.length < 2) return [];
    const probes = ev.roleProbes ?? {};
    const roles = Object.keys(probes);
    if (roles.length < 2) return [];

    const [r1, r2] = [roles[0]!, roles[1]!];
    const aProbes = probes[r1] ?? [];
    const bProbes = probes[r2] ?? [];
    const aMap = new Map(aProbes.map((p) => [p.url, p]));
    const findings = [];
    for (const bp of bProbes) {
      const ap = aMap.get(bp.url);
      if (!ap) continue;
      const both2xx = ap.status >= 200 && ap.status < 300 && bp.status >= 200 && bp.status < 300;
      const sizeDelta = Math.abs(ap.bytes - bp.bytes);
      if (both2xx && sizeDelta < 64) {
        findings.push({
          title: 'Identical response sizes across two roles — verify tenant scoping',
          severity: 'high' as const,
          category: 'multi-tenant',
          description: `Endpoint ${bp.url} returned 2xx responses of nearly identical size to roles "${r1}" and "${r2}". This is unexpected if tenant scoping is enforced.`,
          evidence: {
            url: bp.url,
            [r1]: { status: ap.status, bytes: ap.bytes },
            [r2]: { status: bp.status, bytes: bp.bytes },
          },
          impact: 'Cross-tenant data leakage; one tenant may see another\'s records.',
          remediation:
            'Always scope queries by the authenticated tenant id derived from the session, never from the URL or body. ' +
            'Add an integration test that asserts tenant B receives 404 for tenant A\'s objects.',
          confidence: 'medium' as const,
        });
      }
    }
    return findings;
  },
};
