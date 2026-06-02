import type { SecurityPrompt } from '../../types.js';

export const nosqlInjectionPrompt: SecurityPrompt = {
  id: 'injection.nosql',
  title: 'NoSQL injection surface review',
  category: 'injection',
  severityFocus: 'high',
  prompt: [
    'Goal: Detect endpoints whose JSON bodies are forwarded into NoSQL queries (MongoDB,',
    'CouchDB) without operator-key filtering. Common pattern: `{ email: { $gt: "" } }`',
    'bypasses login.',
    '',
    'Evidence required: login/search endpoints accepting JSON bodies, parameters that look like',
    'filters (q, filter, where).',
    '',
    'Constraints: do NOT submit operator payloads; only flag risky-shaped endpoints for manual',
    'verification.',
    '',
    'Output: severity high when an auth endpoint accepts arbitrary JSON; confidence low without',
    'manual confirmation.',
  ].join('\n'),
};
