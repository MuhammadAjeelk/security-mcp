import type { SecurityPrompt } from '../../types.js';

export const webhookPrompt: SecurityPrompt = {
  id: 'api.webhook',
  title: 'Webhook receiver signature verification',
  category: 'api',
  severityFocus: 'high',
  prompt: [
    'Goal: For inbound webhook endpoints (Stripe, GitHub, Twilio), verify HMAC signature',
    'validation, timestamp tolerance, replay protection.',
    '',
    'Evidence required: discovered endpoints under /webhooks/ or /hooks/; presence of',
    'X-Hub-Signature-256 / Stripe-Signature handling in the response.',
    '',
    'Constraints: do NOT POST forged events. Only inspect endpoint shape.',
    '',
    'Output: severity high if there is no evidence of signature header validation; confidence medium.',
  ].join('\n'),
};
