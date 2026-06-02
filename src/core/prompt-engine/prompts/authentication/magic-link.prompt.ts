import type { SecurityPrompt } from '../../types.js';

export const magicLinkPrompt: SecurityPrompt = {
  id: 'authentication.magic-link',
  title: 'Magic-link replay and expiry',
  category: 'auth',
  severityFocus: 'high',
  prompt: [
    'Goal: Verify that magic links expire, are single-use, are bound to the requesting user',
    'agent / IP where appropriate, and do not log in the wrong account on email mismatch.',
    '',
    'Evidence required: magic-link redemption endpoints, replay attempt response, token length',
    'and entropy assessment.',
    '',
    'Constraints: no token brute-forcing; max 2 redemption attempts per token.',
    '',
    'Output: severity high when a token can be replayed; confidence high only when the second',
    'redemption was actually attempted and succeeded against a non-production target.',
  ].join('\n'),
};
