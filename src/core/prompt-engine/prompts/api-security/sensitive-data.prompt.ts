import type { SecurityPrompt } from '../../types.js';

export const sensitiveDataPrompt: SecurityPrompt = {
  id: 'api.sensitive-data',
  title: 'Sensitive data exposure in responses',
  category: 'api',
  severityFocus: 'high',
  prompt: [
    'Goal: Identify responses that contain secrets, API keys, JWTs in URLs, AWS credentials,',
    'private keys, or PII in plaintext.',
    '',
    'Evidence required: response body fragments matched against well-known secret regexes (AWS,',
    'GitHub, Stripe, Slack); JWT-shaped strings in query strings; password fields returned by APIs.',
    '',
    'Constraints: redact captured values to first/last 4 characters before emitting findings.',
    '',
    'Output: severity high when secrets are observed; confidence high when regex matches.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = ctx.evidence as { pages?: Array<{ finalUrl: string }> };
    const inUrl = (ev.pages ?? []).filter((p) => /[?&](api_key|token|access_token)=/i.test(p.finalUrl));
    if (inUrl.length === 0) return [];
    return [
      {
        title: 'Tokens or keys appear in URL query strings',
        severity: 'high' as const,
        category: 'api',
        description:
          'Tokens/keys in query strings are logged in proxies, CDN access logs and browser history, ' +
          'often outliving the session.',
        evidence: { urls: inUrl.map((p) => p.finalUrl.replace(/=([^&]+)/g, '=<redacted>')) },
        impact: 'Long-lived secret exposure across infrastructure boundaries.',
        remediation: 'Move secrets/tokens out of query strings into Authorization headers or cookies.',
        confidence: 'high' as const,
      },
    ];
  },
};
