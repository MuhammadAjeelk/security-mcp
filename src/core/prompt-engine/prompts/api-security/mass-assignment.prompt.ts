import type { SecurityPrompt } from '../../types.js';

export const massAssignmentPrompt: SecurityPrompt = {
  id: 'api.mass-assignment',
  title: 'Mass assignment in update endpoints',
  category: 'api',
  severityFocus: 'high',
  prompt: [
    'Goal: Detect REST/update endpoints that accept the full model representation without an',
    'explicit field allowlist (`is_admin`, `tenant_id`, `email_verified`).',
    '',
    'Evidence required: PUT/PATCH endpoints with JSON body schemas, forms with hidden fields',
    'that should be server-side.',
    '',
    'Constraints: do not submit payloads beyond what was already discovered.',
    '',
    'Output: severity high; confidence medium without dynamic verification.',
  ].join('\n'),
};
