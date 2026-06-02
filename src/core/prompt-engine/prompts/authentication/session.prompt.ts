import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence } from '../../helpers.js';

export const sessionPrompt: SecurityPrompt = {
  id: 'authentication.session',
  title: 'Session cookie hygiene',
  category: 'auth',
  severityFocus: 'high',
  prompt: [
    'Goal: Verify session/auth cookies use Secure, HttpOnly and SameSite attributes appropriate',
    'to the deployment.',
    '',
    'Evidence required: Set-Cookie headers from login flows and authenticated pages.',
    '',
    'Output: severity scaled by cookie purpose (session > preferences). Confidence high when',
    'the cookie attributes are directly inspected.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const findings = [];
    for (const [url, cookies] of Object.entries(ev.cookies)) {
      for (const cookie of cookies) {
        const lower = cookie.toLowerCase();
        const looksLikeSession = /\b(sid|session|sess|auth|token|jwt)=/.test(lower);
        if (!looksLikeSession) continue;
        const issues: string[] = [];
        if (!lower.includes('httponly')) issues.push('missing HttpOnly');
        if (!lower.includes('secure')) issues.push('missing Secure');
        if (!lower.includes('samesite')) issues.push('missing SameSite');
        if (issues.length > 0) {
          findings.push({
            title: `Session-like cookie lacks security attributes (${issues.join(', ')})`,
            severity: 'medium' as const,
            category: 'auth',
            description:
              'A cookie that appears to carry a session identifier was issued without one or more ' +
              'recommended security attributes.',
            evidence: { url, cookieSample: cookie.split(';')[0], issues },
            impact:
              'Without HttpOnly the cookie is exposed to XSS; without Secure it can be sent over plaintext; ' +
              'without SameSite it is more vulnerable to CSRF.',
            remediation:
              'Set HttpOnly, Secure and SameSite=Lax (or Strict) on session cookies. Re-issue after login.',
            confidence: 'high' as const,
          });
        }
      }
    }
    return findings;
  },
};
