import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence } from '../../helpers.js';

export const csrfPrompt: SecurityPrompt = {
  id: 'api.csrf',
  title: 'Cross-Site Request Forgery (CSRF) protection',
  category: 'api',
  severityFocus: 'high',
  prompt: [
    'Goal: Verify state-changing endpoints require a CSRF token, double-submit cookie, or rely',
    'on a SameSite=Strict/Lax session cookie.',
    '',
    'Evidence required: discovered forms with method=POST and the presence of a token-shaped',
    'hidden input; Set-Cookie SameSite attribute on session cookies.',
    '',
    'Output: severity high when no token AND no SameSite; confidence medium without dynamic test.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const findings = [];
    const tokenLike = /(csrf|xsrf|_token|authenticity)/i;
    for (const form of ev.forms) {
      if (form.method.toUpperCase() === 'GET') continue;
      if (!form.fields.some((f) => tokenLike.test(f))) {
        findings.push({
          title: 'POST form has no CSRF-token-shaped hidden field',
          severity: 'medium' as const,
          category: 'api',
          description:
            `Form at ${form.pageUrl} (action=${form.action ?? form.pageUrl}) is POST but does not ` +
            'contain an obvious CSRF token field.',
          evidence: { pageUrl: form.pageUrl, action: form.action, fields: form.fields },
          impact: 'Without CSRF protection (or SameSite=Strict), attacker sites can forge state changes on behalf of the user.',
          remediation:
            'Add an unpredictable per-session token in a hidden field validated server-side, OR set session ' +
            'cookies to SameSite=Strict/Lax and verify Origin/Referer on state-changing requests.',
          confidence: 'low' as const,
        });
      }
    }
    return findings;
  },
};
