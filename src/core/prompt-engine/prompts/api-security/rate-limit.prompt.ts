import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence, eachHeaders, findHeader } from '../../helpers.js';

export const rateLimitPrompt: SecurityPrompt = {
  id: 'api.rate-limit',
  title: 'Rate limiting and brute-force protection',
  category: 'api',
  severityFocus: 'high',
  prompt: [
    'Goal: Verify that authentication, password reset, OTP, and other abuse-prone endpoints',
    'enforce server-side rate limiting and account lockout.',
    '',
    'Evidence required: presence of X-RateLimit-* or Retry-After response headers on sensitive',
    'endpoints, server response to repeated benign requests.',
    '',
    'Constraints: cap test requests to 5 per endpoint; never run brute force.',
    '',
    'Output: severity high when no rate-limit signal on /login or /reset; confidence medium',
    'unless multiple requests were actually issued and compared.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const findings = [];
    for (const { url, headers } of eachHeaders(ev)) {
      if (!/\b(login|signin|auth|reset|otp|verify)\b/i.test(url)) continue;
      const hasLimit =
        findHeader(headers, 'x-ratelimit-limit') ||
        findHeader(headers, 'ratelimit-limit') ||
        findHeader(headers, 'retry-after');
      if (!hasLimit) {
        findings.push({
          title: 'No rate-limit response headers on sensitive endpoint',
          severity: 'medium' as const,
          category: 'api',
          description:
            `No RateLimit / Retry-After header observed on ${url}. Absence of headers is not proof of ` +
            'no rate limiting, but warrants verification.',
          evidence: { url },
          impact: 'Without rate limiting, credential stuffing and OTP brute force become trivial.',
          remediation:
            'Add per-IP and per-account limits on authentication-adjacent endpoints. Emit Retry-After. ' +
            'Add CAPTCHA or progressive delay after N failures.',
          confidence: 'low' as const,
        });
      }
    }
    return findings;
  },
};
