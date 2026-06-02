import { z } from 'zod';
import { runPromptLoop } from '../../core/prompt-engine/prompt-loop-runner.js';
import { validateTarget } from '../../core/policy/target-policy.js';

const TestAccountSchema = z.object({
  role: z.string().min(1),
  email: z.string().optional(),
  token: z.string().optional(),
  cookies: z.record(z.string(), z.string()).optional(),
});

export const promptLoopInputSchema = z.object({
  targetUrl: z.string().min(1),
  evidence: z.record(z.unknown()),
  loopMode: z.enum(['single-pass', 'iterative']),
  maxIterations: z.number().int().positive().max(20).optional(),
  testAccounts: z.array(TestAccountSchema).optional(),
});

export type PromptLoopInput = z.infer<typeof promptLoopInputSchema>;

export const promptLoopToolDefinition = {
  name: 'run_prompt_loop',
  description:
    'Run the registered security prompts against supplied evidence. Use this when you already ' +
    'have evidence from a previous security_scan and want to re-run the prompt loop (e.g. with ' +
    'additional test accounts).',
  inputSchema: {
    type: 'object',
    properties: {
      targetUrl: { type: 'string' },
      evidence: { type: 'object' },
      loopMode: { type: 'string', enum: ['single-pass', 'iterative'] },
      maxIterations: { type: 'number', minimum: 1, maximum: 20 },
      testAccounts: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            role: { type: 'string' },
            email: { type: 'string' },
            token: { type: 'string' },
            cookies: { type: 'object', additionalProperties: { type: 'string' } },
          },
          required: ['role'],
        },
      },
    },
    required: ['targetUrl', 'evidence', 'loopMode'],
  } as const,
};

export async function handlePromptLoop(input: PromptLoopInput) {
  const decision = validateTarget(input.targetUrl);
  if (!decision.allowed) {
    return { ok: false as const, reason: decision.reason };
  }
  const loop = await runPromptLoop({
    targetUrl: input.targetUrl,
    evidence: input.evidence,
    loopMode: input.loopMode,
    maxIterations: input.maxIterations,
    testAccounts: input.testAccounts,
  });
  return {
    ok: true as const,
    iterations: loop.iterations,
    stopReason: loop.stopReason,
    findings: loop.findings,
  };
}
