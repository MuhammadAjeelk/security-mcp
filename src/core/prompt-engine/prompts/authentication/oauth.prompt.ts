import type { SecurityPrompt } from '../../types.js';

export const oauthPrompt: SecurityPrompt = {
  id: 'authentication.oauth',
  title: 'OAuth / SSO misconfiguration',
  category: 'auth',
  severityFocus: 'high',
  prompt: [
    'Goal: Detect open redirect via redirect_uri, missing state/PKCE, weak scope validation,',
    'token leakage via referer.',
    '',
    'Evidence required: OAuth start endpoints, callback URLs, presence of `state` parameter,',
    'presence of `code_challenge` for public clients.',
    '',
    'Constraints: never exchange tokens beyond local/staging; never use a real provider in test.',
    '',
    'Output: severity high for missing state / weak redirect validation; confidence medium',
    'unless the flow was directly initiated by the scanner.',
  ].join('\n'),
};
