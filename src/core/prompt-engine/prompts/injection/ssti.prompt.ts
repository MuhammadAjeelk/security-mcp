import type { SecurityPrompt } from '../../types.js';

export const sstiPrompt: SecurityPrompt = {
  id: 'injection.ssti',
  title: 'Server-side template injection (SSTI)',
  category: 'injection',
  severityFocus: 'critical',
  prompt: [
    'Goal: Identify endpoints that render user input through a server-side template engine',
    '(Jinja2, Twig, Freemarker, Velocity, ERB, Handlebars, Razor). SSTI commonly escalates to RCE.',
    '',
    'Evidence required: parameters or body fields whose value is reflected into HTML/text; a',
    'guarded arithmetic canary that the server *evaluates* rather than echoes verbatim.',
    '',
    'Method (non-destructive): submit a benign expression in several template syntaxes at once —',
    '`smcp{{7*7}}${7*7}#{7*7}<%=7*7%>`. If the response contains `smcp49` (and NOT the literal',
    '`{{7*7}}`), a template engine evaluated the input. Do NOT attempt RCE payloads, file reads,',
    'or object-traversal gadgets — evaluation of 7*7 is sufficient proof.',
    '',
    'Output: severity critical when the expression evaluates; confidence medium without an RCE',
    'demonstration. Note the engine if its error/output fingerprints it.',
  ].join('\n'),
};
