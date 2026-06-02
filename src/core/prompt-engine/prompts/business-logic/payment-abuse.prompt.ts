import type { SecurityPrompt } from '../../types.js';

export const paymentAbusePrompt: SecurityPrompt = {
  id: 'business-logic.payment-abuse',
  title: 'Payment / checkout flow abuse',
  category: 'payment',
  severityFocus: 'critical',
  prompt: [
    'Goal: Detect checkout flows that trust client-supplied price, currency, quantity, or',
    'discount fields, or that allow re-using payment intents across orders.',
    '',
    'Evidence required: checkout/order POST bodies inferred from forms or scripts, response',
    'fields containing `amount`, `price`, `currency`, `payment_intent_id`.',
    '',
    'Constraints: NEVER place real test charges except against an explicit Stripe/Adyen test',
    'mode in localhost/staging; cap to 1 test order per scan; never alter live payment intents.',
    '',
    'Output: severity critical when price/currency are client-controlled; confidence high only',
    'when a test order was placed and a tampered field was honored.',
  ].join('\n'),
};
