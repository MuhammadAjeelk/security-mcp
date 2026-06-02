import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence, eachHeaders, findHeader } from '../../helpers.js';

interface HeaderCheck {
  header: string;
  severity: 'low' | 'medium' | 'high';
  remediation: string;
}

const REQUIRED: HeaderCheck[] = [
  {
    header: 'strict-transport-security',
    severity: 'medium',
    remediation: 'Add HSTS with max-age >= 31536000; includeSubDomains; preload (production only).',
  },
  {
    header: 'x-content-type-options',
    severity: 'low',
    remediation: 'Send `X-Content-Type-Options: nosniff`.',
  },
  {
    header: 'x-frame-options',
    severity: 'medium',
    remediation: 'Send `X-Frame-Options: DENY` or use CSP `frame-ancestors`.',
  },
  {
    header: 'referrer-policy',
    severity: 'low',
    remediation: 'Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.',
  },
  {
    header: 'content-security-policy',
    severity: 'high',
    remediation: 'Define a strict CSP scoped to first-party origins.',
  },
];

export const securityHeadersPrompt: SecurityPrompt = {
  id: 'config.security-headers',
  title: 'Security response headers',
  category: 'headers',
  severityFocus: 'medium',
  prompt: [
    'Goal: Audit response headers for HSTS, X-Content-Type-Options, X-Frame-Options,',
    'Referrer-Policy and CSP. Report each missing header per response.',
    '',
    'Evidence required: response headers from the root page and at least one HTML deeper page.',
    '',
    'Output: severity per header; confidence high.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const findings = [];
    for (const { url, headers } of eachHeaders(ev)) {
      const isHtml = (findHeader(headers, 'content-type') ?? '').includes('html');
      if (!isHtml) continue;
      for (const check of REQUIRED) {
        if (!findHeader(headers, check.header)) {
          findings.push({
            title: `Missing security header: ${check.header}`,
            severity: check.severity,
            category: 'headers',
            description: `${url} response did not include the ${check.header} header.`,
            evidence: { url, missingHeader: check.header },
            impact: 'Reduced defence in depth against browser-side attacks.',
            remediation: check.remediation,
            confidence: 'high' as const,
          });
        }
      }
    }
    return findings;
  },
};
