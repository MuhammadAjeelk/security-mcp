import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence, eachHeaders, findHeader } from '../../helpers.js';

export const clickjackingPrompt: SecurityPrompt = {
  id: 'headers.clickjacking',
  title: 'Clickjacking / framing protection',
  category: 'headers',
  severityFocus: 'medium',
  prompt: [
    'Goal: Determine whether HTML pages can be framed by a third-party origin, enabling clickjacking',
    '(UI redress) attacks against authenticated actions.',
    '',
    'Evidence required: response headers for HTML pages — specifically X-Frame-Options and the CSP',
    "`frame-ancestors` directive.",
    '',
    'A page is protected if it sends X-Frame-Options: DENY/SAMEORIGIN OR a CSP with a restrictive',
    '`frame-ancestors`. Sensitive, state-changing, or authenticated pages (login, account, admin,',
    'payment) are the highest priority.',
    '',
    'Output: severity medium when an authenticated/sensitive page lacks both protections; low for',
    'a public marketing page; confidence high (header presence is deterministic).',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const findings = [];
    for (const { url, headers } of eachHeaders(ev)) {
      const isHtml = (findHeader(headers, 'content-type') ?? '').includes('html');
      if (!isHtml) continue;
      const xfo = findHeader(headers, 'x-frame-options');
      const csp = findHeader(headers, 'content-security-policy') ?? '';
      const frameAncestors = /frame-ancestors/i.test(csp);
      if (!xfo && !frameAncestors) {
        const sensitive = /(login|signin|account|admin|payment|checkout|settings|profile)/i.test(url);
        findings.push({
          title: 'Page is framable (clickjacking)',
          severity: (sensitive ? 'medium' : 'low') as 'medium' | 'low',
          category: 'headers',
          description: `${url} sends neither X-Frame-Options nor CSP frame-ancestors, so it can be framed by any origin.`,
          evidence: { url, sensitive },
          impact: 'Clickjacking / UI-redress against authenticated actions (e.g. silent state changes).',
          remediation: 'Send `X-Frame-Options: DENY` (or SAMEORIGIN) and a CSP `frame-ancestors \'none\'` directive.',
          confidence: 'high' as const,
        });
      }
    }
    return findings;
  },
};
