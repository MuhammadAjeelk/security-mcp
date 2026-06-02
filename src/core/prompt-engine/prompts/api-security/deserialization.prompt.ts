import type { SecurityPrompt } from '../../types.js';

export const deserializationPrompt: SecurityPrompt = {
  id: 'api.deserialization',
  title: 'Insecure deserialization',
  category: 'api',
  severityFocus: 'critical',
  prompt: [
    'Goal: Identify endpoints that deserialize untrusted input (Java ObjectInputStream, Ruby',
    'Marshal, Python pickle, .NET BinaryFormatter).',
    '',
    'Evidence required: discovered content-types `application/x-java-serialized-object`,',
    '`application/x-python-pickle`; cookie values that decode as serialized objects.',
    '',
    'Constraints: NEVER submit gadget chains; only flag presence of risky deserialization formats.',
    '',
    'Output: severity critical; confidence high only when a vulnerable format is directly observed.',
  ].join('\n'),
};
