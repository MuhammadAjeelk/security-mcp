import type { SecurityPrompt } from '../../types.js';

export const fileUploadPrompt: SecurityPrompt = {
  id: 'files.upload',
  title: 'File upload validation',
  category: 'files',
  severityFocus: 'high',
  prompt: [
    'Goal: Verify upload endpoints validate content-type AND magic bytes, enforce size limits,',
    'strip metadata, store outside the web root, and rename to non-guessable identifiers.',
    '',
    'Evidence required: discovered <input type=file> forms, upload endpoint, response Location',
    'header on success, served Content-Type on retrieval.',
    '',
    'Constraints: do NOT upload binaries; document the gaps based on the discovered form only.',
    '',
    'Output: severity high; confidence medium without a real upload.',
  ].join('\n'),
};
