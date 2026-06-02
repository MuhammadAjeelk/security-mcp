import type { SecurityPrompt } from '../../types.js';

export const cachePoisoningPrompt: SecurityPrompt = {
  id: 'api.cache-poisoning',
  title: 'Cache poisoning risks',
  category: 'api',
  severityFocus: 'medium',
  prompt: [
    'Goal: Identify cacheable responses whose contents depend on uncached request headers',
    '(X-Forwarded-Host, X-Original-URL) — leading to poisoning of shared caches.',
    '',
    'Evidence required: Cache-Control / CDN-Cache-Control headers, Vary header, presence of',
    'request-header reflection.',
    '',
    'Constraints: do NOT submit poisoning payloads against shared caches; flag suspicious Vary',
    'configurations only.',
    '',
    'Output: severity medium; confidence low without dynamic verification.',
  ].join('\n'),
};
