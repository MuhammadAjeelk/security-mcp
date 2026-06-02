import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence, eachHeaders, findHeader } from '../../helpers.js';

export const authBypassPrompt: SecurityPrompt = {
  id: 'authentication.auth-bypass',
  title: 'Authentication bypass surfaces',
  category: 'auth',
  severityFocus: 'critical',
  prompt: [
    'Goal: Identify endpoints that appear to require auth but are reachable unauthenticated, and',
    'detect common bypass vectors (missing middleware, debug overrides, header trust).',
    '',
    'Evidence required: protected-looking paths (account, dashboard, billing, admin),',
    'unauthenticated response codes, presence of header-based auth bypass headers',
    '(X-Original-URL, X-Rewrite-URL, X-Forwarded-User).',
    '',
    'Constraints: only inspect responses; never brute force credentials; never spray tokens.',
    '',
    'Output: severity critical only when an authenticated route is observed returning 2xx',
    'unauthenticated. Otherwise medium with low confidence and a suggested manual follow-up.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const protectedPattern = /\/(account|dashboard|billing|profile|settings|admin)(\/|$)/i;
    const reachable = ev.pages.filter(
      (p) => protectedPattern.test(p.finalUrl) && p.status >= 200 && p.status < 300,
    );
    const out = [];
    if (reachable.length > 0 && ctx.testAccounts.length === 0) {
      out.push({
        title: 'Authenticated-looking pages returned 2xx without supplied credentials',
        severity: 'high' as const,
        category: 'auth',
        description:
          'Pages matching common authenticated patterns responded with 2xx although no test ' +
          'account was supplied. This may indicate missing auth middleware OR simply a public marketing page.',
        evidence: { pages: reachable.slice(0, 5).map((p) => ({ url: p.finalUrl, status: p.status })) },
        impact: 'If genuinely authenticated routes are public, anyone may access private data.',
        remediation:
          'Verify each route is behind authentication middleware. Add tests that assert 401/302 for ' +
          'unauthenticated requests to protected routes.',
        confidence: 'low' as const,
      });
    }
    for (const { url, headers } of eachHeaders(ev)) {
      if (findHeader(headers, 'x-debug-mode') || findHeader(headers, 'x-bypass-auth')) {
        out.push({
          title: 'Server emits debug/bypass headers',
          severity: 'high' as const,
          category: 'auth',
          description: `Response from ${url} exposes a debug or auth-bypass header.`,
          evidence: { url, suspiciousHeaders: headers },
          impact: 'Debug bypass headers, if respected on the server, allow trivial auth bypass.',
          remediation: 'Remove debug/bypass headers from non-local environments.',
          confidence: 'high' as const,
        });
      }
    }
    return out;
  },
};
