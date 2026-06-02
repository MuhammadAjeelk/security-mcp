import type { SecurityPrompt } from '../../types.js';

export const excessiveDataExposurePrompt: SecurityPrompt = {
  id: 'api.excessive-data-exposure',
  title: 'Excessive data exposure / PII leakage in responses',
  category: 'api',
  severityFocus: 'high',
  prompt: [
    'Goal: Detect API responses that include PII, secrets, internal IDs or other sensitive',
    'fields not needed by the client.',
    '',
    'Evidence required: JSON responses returned by discovered endpoints, response shape',
    'including SSN/credit-card patterns, presence of password hashes, internal flags.',
    '',
    'Constraints: redact any captured PII before adding to findings; only keep key names + sample shape.',
    '',
    'Output: severity high when password hashes or PII are returned; confidence high when the',
    'data is in the captured evidence.',
  ].join('\n'),
};
