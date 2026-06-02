import type { SecurityPrompt } from '../../types.js';

export const bflaPrompt: SecurityPrompt = {
  id: 'access-control.bfla',
  title: 'Broken Function Level Authorization (BFLA)',
  category: 'access-control',
  severityFocus: 'high',
  prompt: [
    'Goal: Detect endpoints/actions intended for higher-privilege roles that are reachable by',
    'lower-privilege principals.',
    '',
    'Evidence required: admin-style URL patterns (/admin, /internal, /manage), role-specific',
    'actions discovered in pages or scripts, responses to the same endpoint from two roles.',
    '',
    'Constraints: never execute destructive admin actions; for write verbs, only inspect',
    'whether the endpoint is REACHABLE (e.g., 401 vs 200), never submit payloads.',
    '',
    'Output: severity high if low-privilege role gets 2xx on admin route; confidence medium',
    'unless differential evidence is present.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = ctx.evidence as { endpoints?: Array<{ url: string; method: string }> };
    const eps = ev.endpoints ?? [];
    const adminLike = eps.filter((e) => /\/(admin|internal|manage|root|debug)(\/|$)/i.test(e.url));
    if (adminLike.length === 0) return [];
    return [
      {
        title: 'Admin-style routes discovered — verify role-based access control',
        severity: 'medium',
        category: 'access-control',
        description:
          'Routes matching admin/internal patterns were discovered during crawl. These should ' +
          'return 401/403 for unauthenticated and non-admin principals.',
        evidence: { adminEndpoints: adminLike.slice(0, 10).map((e) => `${e.method} ${e.url}`) },
        impact:
          'If reachable by non-admins, attackers may escalate function-level privileges (BFLA).',
        remediation:
          'Centralize authorization (policy or middleware) and assert role on every admin route. ' +
          'Add tests that hit every admin endpoint as a non-admin and assert 403.',
        confidence: 'low',
      },
    ];
  },
};
