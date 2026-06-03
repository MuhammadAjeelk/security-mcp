import type { SecurityPrompt } from '../../types.js';

export const webCacheDeceptionPrompt: SecurityPrompt = {
  id: 'api.web-cache-deception',
  title: 'Web cache deception / poisoning',
  category: 'api',
  severityFocus: 'high',
  prompt: [
    'Goal: Detect whether a CDN/reverse-proxy cache can be tricked into storing authenticated,',
    'user-specific responses (cache deception) or whether unkeyed inputs can poison shared cache',
    'entries (cache poisoning).',
    '',
    'Evidence required: Cache-Control / Age / X-Cache / CF-Cache-Status / Vary headers on responses;',
    'behaviour of an authenticated page when a static-looking suffix is appended.',
    '',
    'Cache deception (non-destructive): request a sensitive authenticated page with an appended',
    'path segment or extension that the cache treats as static — e.g. `/account/profile.css`,',
    '`/account/profile/smcp.js`, `;.css`. If the app still returns the private content AND a cache',
    'header indicates it was/edge-cached (Age>0, X-Cache: HIT, CF-Cache-Status: HIT), an attacker can',
    'capture another user\'s response from the shared cache.',
    '',
    'Cache poisoning: identify unkeyed inputs (X-Forwarded-Host, X-Forwarded-Scheme, custom headers)',
    'that influence the response but are not part of the cache key; reflected unkeyed input that is',
    'then served to other users is poisoning. Do NOT persist harmful content — detection only.',
    '',
    'Output: severity high on a confirmed deception/poisoning; medium when the cache reflects but',
    'impact is unproven; confidence per the strength of the cache-hit evidence.',
  ].join('\n'),
};
