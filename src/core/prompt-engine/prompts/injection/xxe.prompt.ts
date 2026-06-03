import type { SecurityPrompt } from '../../types.js';

export const xxePrompt: SecurityPrompt = {
  id: 'injection.xxe',
  title: 'XML external entity (XXE) processing',
  category: 'injection',
  severityFocus: 'high',
  prompt: [
    'Goal: Identify endpoints that parse XML (or SVG/SOAP/DOCX/XLSX/RSS) and resolve entities,',
    'enabling file read, SSRF, or denial of service.',
    '',
    'Evidence required: an endpoint accepting application/xml, text/xml, or an XML-bearing upload;',
    'behaviour change when a DOCTYPE with an entity is supplied.',
    '',
    'Method (non-destructive): POST a document declaring a benign INTERNAL entity only —',
    '`<!DOCTYPE smcp [<!ENTITY smcpx "SMCP_XXE_CANARY">]>` referenced as `&smcpx;`. If',
    '`SMCP_XXE_CANARY` appears expanded in the response, the parser resolves entities. Do NOT use',
    'SYSTEM/external entities, file:// , http:// , or parameter entities — internal expansion is',
    'enough to flag the risk.',
    '',
    'Output: severity high when the internal entity expands; confidence low without a controlled',
    'external-fetch confirmation. Recommend disabling DTD/external entities in the parser.',
  ].join('\n'),
};
