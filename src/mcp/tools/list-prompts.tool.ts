import { z } from 'zod';
import { PROMPT_REGISTRY } from '../../core/prompt-engine/prompt-registry.js';

export const listPromptsInputSchema = z.object({
  category: z.string().optional(),
  ids: z.array(z.string()).optional(),
});

export type ListPromptsInput = z.infer<typeof listPromptsInputSchema>;

export const listPromptsToolDefinition = {
  name: 'list_security_prompts',
  description:
    'Return the registry of security prompts (id, title, category, severityFocus, full prompt text) ' +
    'so the CALLING LLM can apply each against scan evidence and reason natively. This is the ' +
    'recommended workflow when the MCP is used from Claude Code or Cursor — no server-side LLM ' +
    'call is needed.',
  inputSchema: {
    type: 'object',
    properties: {
      category: {
        type: 'string',
        description: 'Optional. Filter prompts by category (e.g. "auth", "injection").',
      },
      ids: {
        type: 'array',
        items: { type: 'string' },
        description: 'Optional. Return only prompts with these ids.',
      },
    },
  } as const,
};

export function handleListPrompts(input: ListPromptsInput) {
  let prompts = [...PROMPT_REGISTRY];
  if (input.category) {
    prompts = prompts.filter((p) => p.category === input.category);
  }
  if (input.ids && input.ids.length > 0) {
    const set = new Set(input.ids);
    prompts = prompts.filter((p) => set.has(p.id));
  }
  return {
    count: prompts.length,
    prompts: prompts.map((p) => ({
      id: p.id,
      title: p.title,
      category: p.category,
      severityFocus: p.severityFocus,
      prompt: p.prompt,
    })),
    usage:
      'For each prompt, evaluate it against the evidence object returned by security_scan. Emit ' +
      'findings yourself with the standard shape: { title, severity, confidence, category, description, ' +
      'evidence, impact, remediation }. When done, submit all findings via generate_report.',
  };
}
