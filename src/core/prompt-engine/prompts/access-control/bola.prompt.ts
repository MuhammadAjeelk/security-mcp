import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence } from '../../helpers.js';

export const bolaPrompt: SecurityPrompt = {
  id: 'access-control.bola',
  title: 'Broken Object Level Authorization (BOLA)',
  category: 'access-control',
  severityFocus: 'high',
  prompt: [
    'Goal: Verify that object-level authorization is enforced on each API endpoint that returns,',
    'mutates or deletes a single object.',
    '',
    'Evidence required: at least two test accounts with different ownership scopes, endpoint',
    'list, response status codes for the foreign principal.',
    '',
    'Constraints: only read operations against allowed targets; do NOT issue mutating verbs',
    'against another tenant\'s data even on staging.',
    '',
    'Output: severity high if foreign principal receives 2xx with data; severity medium if 200 with empty body;',
    'confidence high only when differential evidence between two accounts is captured.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    if (ctx.testAccounts.length < 2) {
      return [
        {
          title: 'BOLA cannot be verified — fewer than two test accounts provided',
          severity: 'info',
          category: 'access-control',
          description:
            'Broken Object Level Authorization can only be proven by issuing the same request as ' +
            'two distinct principals and comparing responses. Supply at least two `testAccounts` ' +
            'with different roles or ownership scopes to enable this check.',
          evidence: { providedAccounts: ctx.testAccounts.length },
          impact: 'BOLA findings will be missed until multi-account evidence is supplied.',
          remediation:
            'Pass two or more test accounts via the security_scan tool input so the loop can perform differential checks.',
          confidence: 'high',
        },
      ];
    }

    const probes = ev.roleProbes ?? {};
    const roles = Object.keys(probes);
    if (roles.length < 2) return [];

    // Look for endpoints where one role gets 2xx and another gets 401/403 — likely
    // protected. Then flag endpoints where BOTH roles get 2xx as needing manual review.
    const byUrl: Record<string, Array<{ role: string; status: number }>> = {};
    for (const role of roles) {
      for (const probe of probes[role] ?? []) {
        if (!byUrl[probe.url]) byUrl[probe.url] = [];
        byUrl[probe.url]!.push({ role, status: probe.status });
      }
    }

    const suspect: Array<{ url: string; statuses: Array<{ role: string; status: number }> }> = [];
    for (const [url, statuses] of Object.entries(byUrl)) {
      const has2xx = statuses.some((s) => s.status >= 200 && s.status < 300);
      const has4xx = statuses.some((s) => s.status === 401 || s.status === 403);
      const allOk = statuses.every((s) => s.status >= 200 && s.status < 300);
      // Endpoint that returns 401/403 to one role and 2xx to another that ALSO
      // shouldn't have access (e.g. peer tenant) — flag.
      if (has2xx && has4xx) {
        suspect.push({ url, statuses });
      } else if (allOk && statuses.length > 1) {
        suspect.push({ url, statuses });
      }
    }

    if (suspect.length === 0) return [];
    return [
      {
        title: 'Differential role probe surfaced shared 2xx responses — verify per-object ownership',
        severity: 'high',
        category: 'access-control',
        description:
          'Discovered endpoints returned 2xx for more than one role, OR the auth boundary differs ' +
          'inconsistently across roles. Manually inspect to confirm whether resource ownership is enforced.',
        evidence: { suspect: suspect.slice(0, 10) },
        impact: 'If ownership is not checked, one tenant/user can read another\'s data.',
        remediation:
          'For every object-fetching endpoint, assert principal owns the resource (or has explicit permission) ' +
          'before returning data. Cover with integration tests using two distinct accounts.',
        confidence: 'medium',
      },
    ];
  },
};
