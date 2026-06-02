import type { SecurityPrompt } from '../../types.js';

export const workflowBypassPrompt: SecurityPrompt = {
  id: 'business-logic.workflow-bypass',
  title: 'Multi-step workflow / state transition bypass',
  category: 'business-logic',
  severityFocus: 'high',
  prompt: [
    'Goal: Detect endpoints that allow skipping required prior steps (KYC -> withdraw, signup',
    '-> verify-email -> purchase) by calling the final step directly.',
    '',
    'Evidence required: enumerated step endpoints, whether the final step rejects when prior',
    'state is missing.',
    '',
    'Constraints: never bypass on production tenants; never withdraw funds; read-only probing.',
    '',
    'Output: severity high; confidence high only with dynamic state-skip evidence.',
  ].join('\n'),
};
