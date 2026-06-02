import type { SecurityPrompt } from '../../types.js';

export const roleEscalationPrompt: SecurityPrompt = {
  id: 'access-control.role-escalation',
  title: 'Role escalation via mass assignment / role parameter tampering',
  category: 'access-control',
  severityFocus: 'critical',
  prompt: [
    'Goal: Identify endpoints that accept user-provided `role`, `is_admin`, `permissions`,',
    '`scope` or similar fields and bind them to server-side models without an allowlist.',
    '',
    'Evidence required: form fields, JSON request bodies inferred from inline scripts, profile',
    'update endpoints, registration endpoints.',
    '',
    'Constraints: never actually escalate privileges; only inspect whether suspicious fields are',
    'accepted, never assert against production tenants.',
    '',
    'Output: severity critical when a write endpoint binds role-like fields; confidence high',
    'only when the field is observed to be honored.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = ctx.evidence as { forms?: Array<{ pageUrl: string; fields: string[]; method: string; action?: string }> };
    const dangerousNames = ['role', 'roles', 'is_admin', 'isAdmin', 'permissions', 'scope', 'admin'];
    const hits = (ev.forms ?? []).filter((f) =>
      f.fields.some((field) => dangerousNames.includes(field)),
    );
    if (hits.length === 0) return [];
    return [
      {
        title: 'Forms accept role-like fields — verify allowlist on server',
        severity: 'high',
        category: 'access-control',
        description:
          'One or more discovered forms include privilege-bearing fields (e.g. role, is_admin). ' +
          'These must never be bound directly to server-side user models.',
        evidence: {
          forms: hits.map((f) => ({
            pageUrl: f.pageUrl,
            method: f.method,
            action: f.action,
            fields: f.fields,
          })),
        },
        impact: 'Attackers may escalate privileges by submitting `role=admin` during signup or profile update.',
        remediation:
          'Use strict allowlists when mapping request body → user model. Never trust client-supplied role. ' +
          'Add an integration test that submits `role=admin` and asserts the server ignores it.',
        confidence: 'medium',
      },
    ];
  },
};
