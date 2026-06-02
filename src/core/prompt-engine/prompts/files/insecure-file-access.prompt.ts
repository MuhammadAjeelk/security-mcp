import type { SecurityPrompt } from '../../types.js';

export const insecureFileAccessPrompt: SecurityPrompt = {
  id: 'files.insecure-access',
  title: 'Insecure direct file access',
  category: 'files',
  severityFocus: 'high',
  prompt: [
    'Goal: Detect static file serving over user IDs (e.g. /uploads/<userId>/avatar.png) without',
    'an authorization check, and missing cache-control on sensitive files.',
    '',
    'Evidence required: page links to /uploads, /files, /downloads with predictable shapes;',
    'response headers on a sample fetch.',
    '',
    'Constraints: only fetch already-discovered URLs.',
    '',
    'Output: severity high if private documents are world-readable; confidence medium without dynamic check.',
  ].join('\n'),
};
