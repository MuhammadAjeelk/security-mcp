import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence } from '../../helpers.js';

/** High-confidence secret patterns (provider-prefixed; low false-positive). */
const SECRET_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: 'AWS access key id', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { name: 'Slack token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { name: 'Stripe secret key', re: /\bsk_live_[0-9A-Za-z]{16,}\b/ },
  { name: 'GitHub token', re: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/ },
  { name: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'Generic bearer/jwt in url', re: /[?&](?:api[_-]?key|token|secret|access_token)=[^&\s]{12,}/i },
];

export const secretScanningPrompt: SecurityPrompt = {
  id: 'configuration.secret-scanning',
  title: 'Leaked secrets / credentials in client-reachable content',
  category: 'configuration',
  severityFocus: 'high',
  prompt: [
    'Goal: Find secrets exposed to the client — API keys, tokens, private keys, DB connection',
    'strings — embedded in HTML, inline scripts, JS bundles, JSON responses, source maps,',
    'comments, or query strings.',
    '',
    'Evidence required: response/JS-bundle bodies; discovered endpoint URLs; any *.map source maps;',
    'config-ish files surfaced by content discovery (.env, config.json, etc).',
    '',
    'Method: scan reachable content for provider-prefixed key formats (AKIA…, AIza…, sk_live_…,',
    'gh[pousr]_…), private-key PEM blocks, and `?api_key=`/`?token=` query parameters. For any hit,',
    'do NOT use the credential — report it and recommend immediate rotation.',
    '',
    'Output: severity high (critical if a live cloud/payment key), confidence high on a format match;',
    'note where it was found so it can be rotated and removed from client-reachable code.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const findings = [];
    // Deterministically scan what we hold: endpoint URLs and crawl notes.
    const haystacks: Array<{ where: string; text: string }> = [
      ...ev.endpoints.map((e) => ({ where: e.url, text: e.url })),
      ...(ev.notes ?? []).map((n, i) => ({ where: `note[${i}]`, text: n })),
    ];
    for (const { where, text } of haystacks) {
      for (const pat of SECRET_PATTERNS) {
        if (pat.re.test(text)) {
          findings.push({
            title: `Possible leaked secret: ${pat.name}`,
            severity: 'high' as const,
            category: 'configuration',
            description: `A value matching the ${pat.name} format is reachable at ${where}.`,
            evidence: { where, pattern: pat.name },
            impact: 'Exposed credentials enable account/cloud/payment compromise.',
            remediation: 'Rotate the credential immediately and remove it from client-reachable content; move secrets server-side.',
            confidence: 'medium' as const,
          });
        }
      }
    }
    return findings;
  },
};
