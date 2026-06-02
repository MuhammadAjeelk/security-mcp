import type { SecurityPrompt } from '../../types.js';

export const openRedirectPrompt: SecurityPrompt = {
  id: 'api.open-redirect',
  title: 'Open redirect parameters',
  category: 'api',
  severityFocus: 'medium',
  prompt: [
    'Goal: Detect redirect-driving parameters (`next`, `redirect`, `return_to`, `continue`,',
    '`url`) that accept arbitrary external hosts.',
    '',
    'Evidence required: discovered URLs containing such parameters; for each, validate that the',
    'server only redirects to allowlisted destinations.',
    '',
    'Constraints: do NOT submit a destination outside the allowlist; flag suspicious shape only.',
    '',
    'Output: severity medium; high when combined with OAuth callback paths.',
  ].join('\n'),
};
