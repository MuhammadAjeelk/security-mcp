import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence } from '../../helpers.js';

export const jwtPrompt: SecurityPrompt = {
  id: 'authentication.jwt',
  title: 'JWT issuance and validation hygiene',
  category: 'auth',
  severityFocus: 'high',
  prompt: [
    'Goal: Detect weak JWT practices: alg=none acceptance, weak HMAC keys, long-lived tokens,',
    'missing audience/issuer validation, sensitive claims in the payload.',
    '',
    'Evidence required: tokens visible in response bodies, Authorization headers, set-cookie,',
    '`__Secure-` prefixed cookies, login response payloads.',
    '',
    'Constraints: do NOT attempt to forge tokens; do NOT submit alg=none tokens at endpoints',
    'on hosts that are not local; only DECODE captured tokens for inspection.',
    '',
    'Output: severity high when alg=none/HS256-with-likely-weak-secret/long-lived tokens are',
    'observed; confidence high only when a token is captured AND decoded.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const jwtLike = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;
    const out = [];
    for (const [url, cookies] of Object.entries(ev.cookies)) {
      for (const c of cookies) {
        if (jwtLike.test(c)) {
          const tokenMatch = c.match(jwtLike);
          const decoded = tokenMatch ? safeDecodeHeader(tokenMatch[0]) : null;
          if (decoded?.alg === 'none') {
            out.push({
              title: 'JWT with alg=none observed',
              severity: 'critical' as const,
              category: 'auth',
              description: `A JWT issued at ${url} declares alg=none, which disables signature verification.`,
              evidence: { url, header: decoded },
              impact: 'Attackers can forge arbitrary tokens (any identity, any role).',
              remediation: 'Reject alg=none server-side. Pin allowed algorithms (e.g., RS256/EdDSA).',
              confidence: 'high' as const,
            });
          }
        }
      }
    }
    return out;
  },
};

function safeDecodeHeader(token: string): { alg?: string; typ?: string } | null {
  try {
    const [headerB64] = token.split('.');
    if (!headerB64) return null;
    const padded = headerB64.replace(/-/g, '+').replace(/_/g, '/');
    const json = Buffer.from(padded, 'base64').toString('utf8');
    return JSON.parse(json) as { alg?: string; typ?: string };
  } catch {
    return null;
  }
}
