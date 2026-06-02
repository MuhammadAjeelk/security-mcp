import type { SecurityPrompt } from '../../types.js';

export const commandInjectionPrompt: SecurityPrompt = {
  id: 'injection.command',
  title: 'OS command injection surface',
  category: 'injection',
  severityFocus: 'critical',
  prompt: [
    'Goal: Detect endpoints that shell out (image processors, PDF generators, ping/diagnostic',
    'utilities, git clone interfaces).',
    '',
    'Evidence required: URL paths containing diag/ping/convert/export, file-format parameters,',
    'response timing differences with benign markers.',
    '',
    'Constraints: NO shell metacharacters injected; only inspect routes and parameter shapes.',
    '',
    'Output: severity critical with high confidence ONLY on confirmed code execution evidence;',
    'otherwise flag as manual-review with low confidence.',
  ].join('\n'),
};
