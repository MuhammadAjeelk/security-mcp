import type { SecurityPrompt } from '../../types.js';

export const pathTraversalPrompt: SecurityPrompt = {
  id: 'injection.path-traversal',
  title: 'Path traversal in file-serving endpoints',
  category: 'injection',
  severityFocus: 'high',
  prompt: [
    'Goal: Detect endpoints that serve files based on user-supplied paths/IDs without canonical',
    'path normalization and allowlist.',
    '',
    'Evidence required: endpoints with `filename`, `file`, `path`, `template`, `download`',
    'parameters; response Content-Type when served.',
    '',
    'Constraints: do NOT submit `../etc/passwd` style probes; only flag suspicious shapes.',
    '',
    'Output: medium severity, low confidence unless dynamic verification is performed manually.',
  ].join('\n'),
};
