import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence, eachHeaders, findHeader } from '../../helpers.js';

export const errorLeakagePrompt: SecurityPrompt = {
  id: 'config.error-leakage',
  title: 'Stack trace and server banner leakage',
  category: 'configuration',
  severityFocus: 'medium',
  prompt: [
    'Goal: Detect responses that leak server banners, framework versions, or stack traces.',
    '',
    'Evidence required: Server / X-Powered-By headers; 5xx response bodies if any were captured.',
    '',
    'Output: severity medium; confidence high when headers were directly captured.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const findings = [];
    for (const { url, headers } of eachHeaders(ev)) {
      const server = findHeader(headers, 'server');
      const powered = findHeader(headers, 'x-powered-by');
      if (server && /\d/.test(server)) {
        findings.push({
          title: 'Server banner discloses version',
          severity: 'low' as const,
          category: 'configuration',
          description: `${url} responds with Server: ${server}.`,
          evidence: { url, server },
          impact: 'Version disclosure aids targeted exploit selection.',
          remediation: 'Strip or generalize the Server header in the reverse proxy / framework config.',
          confidence: 'high' as const,
        });
      }
      if (powered) {
        findings.push({
          title: 'X-Powered-By header present',
          severity: 'low' as const,
          category: 'configuration',
          description: `${url} responds with X-Powered-By: ${powered}.`,
          evidence: { url, xPoweredBy: powered },
          impact: 'Discloses framework / language to attackers.',
          remediation: 'Disable X-Powered-By in framework configuration.',
          confidence: 'high' as const,
        });
      }
    }
    return findings;
  },
};
