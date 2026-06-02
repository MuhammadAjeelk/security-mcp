import type { SecurityPrompt } from '../../types.js';

export const privilegeEscalationPrompt: SecurityPrompt = {
  id: 'access-control.privilege-escalation',
  title: 'Vertical / horizontal privilege escalation',
  category: 'access-control',
  severityFocus: 'critical',
  prompt: [
    'Goal: Detect whether a lower-privileged user can reach higher-privileged functionality',
    '(vertical) or another peer\'s resources (horizontal).',
    '',
    'Evidence required: two test accounts in different roles; protected endpoint list; response',
    'codes for both accounts on each endpoint.',
    '',
    'Constraints: read-only probing; never use the higher-privileged account to mutate data on',
    'behalf of the lower-privileged one.',
    '',
    'Output: severity critical with high confidence ONLY when differential evidence shows the',
    'lower role receives data/2xx for protected functionality; otherwise low confidence.',
  ].join('\n'),
};
