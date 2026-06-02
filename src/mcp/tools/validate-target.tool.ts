import { z } from 'zod';
import { validateTarget } from '../../core/policy/target-policy.js';

export const validateTargetInputSchema = z.object({
  targetUrl: z.string().min(1, 'targetUrl is required'),
  allowedHosts: z.array(z.string()).optional(),
});

export type ValidateTargetInput = z.infer<typeof validateTargetInputSchema>;

export const validateTargetToolDefinition = {
  name: 'validate_target',
  description:
    'Validate whether a URL is allowed under the security-mcp target policy. Always run this ' +
    'before any scan. Returns allowed:false with a reason if the URL is rejected.',
  inputSchema: {
    type: 'object',
    properties: {
      targetUrl: { type: 'string', description: 'The URL to validate' },
      allowedHosts: {
        type: 'array',
        items: { type: 'string' },
        description: 'Optional extra hostnames to allowlist for this single call',
      },
    },
    required: ['targetUrl'],
  } as const,
};

export function handleValidateTarget(input: ValidateTargetInput) {
  return validateTarget(input.targetUrl, { extraAllowedHosts: input.allowedHosts });
}
