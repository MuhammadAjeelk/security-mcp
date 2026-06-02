import type { SecurityPrompt } from '../../types.js';

export const ssrfPrompt: SecurityPrompt = {
  id: 'injection.ssrf',
  title: 'Server-Side Request Forgery (SSRF)',
  category: 'injection',
  severityFocus: 'critical',
  prompt: [
    'Goal: Detect endpoints that accept a URL/host parameter and fetch it server-side without',
    'an allowlist (image proxies, webhook testers, OEmbed lookups).',
    '',
    'Evidence required: parameters named `url`, `target`, `callback`, `webhook`, `image_url`,',
    '`redirect`, `next`.',
    '',
    'Constraints: NEVER point a candidate SSRF endpoint at 169.254.169.254 or any cloud',
    'metadata IP — the scanner blocks this anyway. Flag suspicious shape only.',
    '',
    'Output: severity critical with high confidence ONLY if metadata service was reached;',
    'otherwise medium, low confidence.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = ctx.evidence as { endpoints?: Array<{ url: string }>; pages?: Array<{ finalUrl: string }> };
    const urlParamRe = /[?&](url|target|callback|webhook|image_url|next|redirect)=/i;
    const eps = ev.endpoints ?? [];
    const pages = ev.pages ?? [];
    const hits = [
      ...eps.filter((e) => urlParamRe.test(e.url)).map((e) => e.url),
      ...pages.filter((p) => urlParamRe.test(p.finalUrl)).map((p) => p.finalUrl),
    ];
    if (hits.length === 0) return [];
    return [
      {
        title: 'Endpoints accept URL-like parameters — verify SSRF allowlist',
        severity: 'medium' as const,
        category: 'injection',
        description:
          'Parameters that commonly drive server-side fetches were discovered. Ensure each is ' +
          'validated against an allowlist of hosts/schemes before any outbound request.',
        evidence: { urls: hits.slice(0, 10) },
        impact: 'SSRF can pivot to internal services, cloud metadata, or other tenants.',
        remediation:
          'Validate URLs strictly. Block link-local/private IPs, only allow https, resolve DNS once and pin. ' +
          'Use an egress proxy with explicit allowlist where possible.',
        confidence: 'low' as const,
      },
    ];
  },
};
