import type { SecurityPrompt } from '../../types.js';

export const couponAbusePrompt: SecurityPrompt = {
  id: 'business-logic.coupon-abuse',
  title: 'Coupon / promo code abuse',
  category: 'payment',
  severityFocus: 'high',
  prompt: [
    'Goal: Verify that coupon stacking, single-use enforcement and per-account limits are',
    'enforced server-side, not just in the UI.',
    '',
    'Evidence required: coupon redemption endpoint, response shape, presence of server-side',
    'usage counter.',
    '',
    'Constraints: at most 2 redemption attempts; never abuse production discount codes.',
    '',
    'Output: severity high for client-side-only limits; confidence medium without dynamic test.',
  ].join('\n'),
};
