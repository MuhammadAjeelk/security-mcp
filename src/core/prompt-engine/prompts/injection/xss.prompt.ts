import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence, eachHeaders, findHeader } from '../../helpers.js';

export const xssPrompt: SecurityPrompt = {
  id: 'injection.xss',
  title: 'Cross-Site Scripting (reflected/stored)',
  category: 'injection',
  severityFocus: 'high',
  prompt: [
    'Goal: Identify pages that reflect URL parameters without contextual encoding, or accept',
    'user content that is rendered without sanitization.',
    '',
    'Evidence required: pages whose response contains literal query-string values; absence of',
    'Content-Security-Policy headers; absence of X-XSS-Protection; framework templating in use.',
    '',
    'Constraints: NO live payload injection; use only `__SMCP_XSS__` as a benign marker if any.',
    '',
    'Output: severity high when reflection observed without encoding; confidence medium without',
    'browser-driven verification.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const findings = [];
    for (const { url, headers } of eachHeaders(ev)) {
      const csp = findHeader(headers, 'content-security-policy');
      if (!csp) {
        findings.push({
          title: 'Missing Content-Security-Policy',
          severity: 'medium' as const,
          category: 'injection',
          description: `No CSP header on ${url}. CSP is the primary defence-in-depth against XSS.`,
          evidence: { url },
          impact: 'A successful XSS will have full reign of the DOM and outbound network.',
          remediation:
            "Add a strict CSP, e.g. `default-src 'self'; object-src 'none'; base-uri 'self'`. " +
            'Iterate to nonce-based script-src.',
          confidence: 'high' as const,
        });
      }
    }
    return findings;
  },
};
