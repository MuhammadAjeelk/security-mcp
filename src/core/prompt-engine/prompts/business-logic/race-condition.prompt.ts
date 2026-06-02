import type { SecurityPrompt } from '../../types.js';

export const raceConditionPrompt: SecurityPrompt = {
  id: 'business-logic.race-condition',
  title: 'TOCTOU / race-condition risks',
  category: 'business-logic',
  severityFocus: 'high',
  prompt: [
    'Goal: Identify endpoints performing non-atomic check-then-act sequences (gift card',
    'redemption, balance deduction, voucher use, friend invites).',
    '',
    'Evidence required: endpoint list and HTTP verbs; response shape indicating a balance,',
    'token, or counter.',
    '',
    'Constraints: cap any concurrency tests to 3 parallel requests; only against localhost/',
    'staging; never against payment endpoints in production.',
    '',
    'Output: severity high; confidence high only with reproduced race; otherwise medium.',
  ].join('\n'),
};
