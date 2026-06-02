import type { SecurityPrompt } from '../../types.js';

export const passwordResetPrompt: SecurityPrompt = {
  id: 'authentication.password-reset',
  title: 'Password reset flow safety',
  category: 'auth',
  severityFocus: 'high',
  prompt: [
    'Goal: Inspect the password reset flow for token predictability, lack of invalidation after',
    'use, host header injection, user enumeration via differing error messages.',
    '',
    'Evidence required: reset-password URLs discovered during crawl, response bodies that vary',
    'based on whether the email exists, any reset emails shown in test fixtures.',
    '',
    'Constraints: do NOT trigger real password resets at scale; cap to 2 reset requests per scan;',
    'do NOT brute-force tokens.',
    '',
    'Output: severity high when token reuse is observed or host header is reflected; confidence',
    'medium without dynamic verification.',
  ].join('\n'),
};
