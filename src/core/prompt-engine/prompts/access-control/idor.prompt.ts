import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence } from '../../helpers.js';

export const idorPrompt: SecurityPrompt = {
  id: 'access-control.idor',
  title: 'Insecure Direct Object Reference (IDOR)',
  category: 'access-control',
  severityFocus: 'high',
  prompt: [
    'Goal: Detect endpoints that expose resources by predictable IDs without verifying that the',
    'authenticated principal owns or may access them.',
    '',
    'Evidence required: discovered endpoints with numeric/uuid path or query parameters,',
    'response status and bodies for each enumerated ID, contrast between two test accounts.',
    '',
    'Constraints: only enumerate within allowed localhost/staging targets; never modify or',
    'delete resources; max 3 ID variants per endpoint to avoid abusive scanning.',
    '',
    'Output: structured findings with severity, confidence, evidence excerpt (≤500 chars),',
    'impact, remediation. Never claim certainty without two-account differential evidence.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const suspects = ev.endpoints.filter((e) => /\/(\d+|[0-9a-f-]{8,})(\/|$|\?)/i.test(e.url));
    if (suspects.length === 0) return [];
    const sample = suspects.slice(0, 5).map((e) => `${e.method} ${e.url}`);
    return [
      {
        title: 'Endpoints expose object IDs in paths — verify ownership enforcement',
        severity: 'medium',
        category: 'access-control',
        description:
          'One or more discovered endpoints accept object identifiers in the URL. Without an ' +
          'authenticated differential test using at least two distinct roles, IDOR cannot be ruled out.',
        evidence: { suspectEndpoints: sample, totalSuspects: suspects.length },
        impact:
          'If ownership is not enforced, attackers can read or modify resources belonging to other tenants/users.',
        remediation:
          'Enforce per-request ownership checks server-side. Prefer opaque, unguessable IDs (UUIDv4/ULID). ' +
          'Add automated tests that issue the same request as two different principals and assert 403/404 for the non-owner.',
        confidence: 'low',
      },
    ];
  },
};
