import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence, eachHeaders, findHeader } from '../../helpers.js';

export const corsPrompt: SecurityPrompt = {
  id: 'api.cors',
  title: 'CORS misconfiguration',
  category: 'api',
  severityFocus: 'high',
  prompt: [
    'Goal: Detect overly permissive CORS that combines `Access-Control-Allow-Origin: *` (or',
    'reflected origin) with `Access-Control-Allow-Credentials: true`, or that whitelists null',
    'origin.',
    '',
    'Evidence required: preflight and main responses with ACAO/ACAC headers.',
    '',
    'Output: severity high when credentials + wildcard; high when null origin allowed;',
    'confidence high when headers were directly captured.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const findings = [];
    for (const { url, headers } of eachHeaders(ev)) {
      const acao = findHeader(headers, 'access-control-allow-origin');
      const acac = findHeader(headers, 'access-control-allow-credentials');
      if (!acao) continue;
      if (acao === '*' && acac && acac.toLowerCase() === 'true') {
        findings.push({
          title: 'CORS allows credentials with wildcard origin',
          severity: 'critical' as const,
          category: 'api',
          description: `${url} returns ACAO:* with ACAC:true — browsers will reject, but the intent reveals likely misconfiguration.`,
          evidence: { url, acao, acac },
          impact: 'When the origin is reflected instead of `*`, attacker sites can read credentialed responses.',
          remediation: 'Never combine credentials with wildcard. Maintain an explicit origin allowlist.',
          confidence: 'high' as const,
        });
      } else if (acao === 'null') {
        findings.push({
          title: 'CORS allows null origin',
          severity: 'high' as const,
          category: 'api',
          description: `${url} permits the special "null" origin — sandboxed iframes and data: URLs gain access.`,
          evidence: { url, acao },
          impact: 'Attacker-controlled sandboxed contexts can read responses.',
          remediation: 'Remove "null" from the allowlist. Validate origin against a known list.',
          confidence: 'high' as const,
        });
      }
    }
    return findings;
  },
};
