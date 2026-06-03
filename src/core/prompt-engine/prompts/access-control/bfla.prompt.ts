import type { SecurityPrompt } from '../../types.js';

export const bflaPrompt: SecurityPrompt = {
  id: 'access-control.bfla',
  title: 'Broken Function Level Authorization (BFLA)',
  category: 'access-control',
  severityFocus: 'high',
  prompt: [
    'Goal: Detect endpoints/actions intended for higher-privilege roles that are reachable by',
    'lower-privilege or unauthenticated principals (OWASP API5:2023).',
    '',
    'Evidence required: admin-style URL patterns (/admin, /internal, /manage, /actuator), role-',
    'specific actions found in pages/scripts/API spec, responses to the same endpoint from two roles.',
    '',
    'Techniques to apply (read-only):',
    '  1. Call each admin route UNAUTHENTICATED — any 2xx = critical break.',
    '  2. Call it as a LOW-PRIVILEGE account — non-admin 2xx on an admin function = high.',
    '  3. METHOD SWAP: if GET is gated, try HEAD/OPTIONS (and reason about POST/PUT/DELETE without',
    '     executing them) — gates are often method-specific (405 = blocked, secure-leaning).',
    '  4. HEADER BYPASS: replay with X-Forwarded-For:127.0.0.1, X-Real-IP, X-Custom-IP-Authorization,',
    '     X-Original-URL:/admin, X-Rewrite-URL, X-Forwarded-Host, Role:admin, X-Role:admin.',
    '  5. PATH NORMALIZATION: /admin/..;/ , //admin, /Admin, trailing %2f, %2e variants.',
    '',
    'Constraints: never execute destructive admin actions; for write verbs only inspect REACHABILITY',
    '(401/403 vs 2xx), never submit state-changing payloads.',
    '',
    'Verdict rule: VULNERABLE only on 2xx WITH a body that differs from the gated baseline (diff body',
    'length/hash, not status alone — guards against soft-200 error pages). 401/403 = secure, 405 =',
    'method-blocked, 404 = ambiguous-but-denied.',
    '',
    'Output: severity critical (unauth) / high (low-priv or header-bypass); confidence high when a',
    'status-flip + body-diff is shown, medium otherwise. (The BFLA prober automates 1/4/2 read-only.)',
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
