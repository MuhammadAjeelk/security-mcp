import type { LLMClient, LLMCompletionInput } from './llm-client.js';
import { getEnv } from '../../config/env.js';

/**
 * Optional Anthropic-backed LLM client for HEADLESS / CI / cron contexts.
 *
 * NOT NEEDED when this MCP is called from Claude Code or Cursor — in those
 * contexts the calling LLM is already the reasoner. Use `list_security_prompts`
 * from the client side instead and let the calling LLM apply the prompts to
 * scan evidence directly.
 *
 * The `@anthropic-ai/sdk` package is an optional dependency; this module
 * imports it lazily so default installs are lighter.
 */
export class AnthropicLLMClient implements LLMClient {
  private clientPromise: Promise<AnthropicLike> | null = null;
  private readonly apiKey: string;
  private readonly model: string;
  private readonly maxTokens: number;

  constructor(opts?: { apiKey?: string; model?: string; maxTokens?: number }) {
    const env = getEnv();
    this.apiKey = opts?.apiKey ?? env.ANTHROPIC_API_KEY;
    if (!this.apiKey) {
      throw new Error(
        'ANTHROPIC_API_KEY is not set. Set it before using LLM_PROVIDER=anthropic.',
      );
    }
    this.model = opts?.model ?? env.LLM_MODEL;
    this.maxTokens = opts?.maxTokens ?? env.LLM_MAX_TOKENS;
  }

  private async getClient(): Promise<AnthropicLike> {
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        try {
          const mod = (await import('@anthropic-ai/sdk')) as {
            default: new (cfg: { apiKey: string }) => AnthropicLike;
          };
          return new mod.default({ apiKey: this.apiKey });
        } catch {
          throw new Error(
            'AnthropicLLMClient requires the optional `@anthropic-ai/sdk` package. Install with `npm i @anthropic-ai/sdk`.',
          );
        }
      })();
    }
    return this.clientPromise;
  }

  async complete(input: LLMCompletionInput): Promise<string> {
    const client = await this.getClient();
    const evidenceJson = JSON.stringify(input.evidence ?? null);
    const response = await client.messages.create({
      model: this.model,
      max_tokens: this.maxTokens,
      system: [
        {
          type: 'text',
          text: input.systemPrompt,
          cache_control: { type: 'ephemeral' },
        },
      ],
      messages: [
        {
          role: 'user',
          content: [
            {
              type: 'text',
              text:
                `# Prompt\n${input.userPrompt}\n\n# Evidence (JSON)\n\`\`\`json\n${evidenceJson}\n\`\`\`\n\n` +
                'Respond ONLY with a JSON object of the form `{ "findings": [...] }`. ' +
                'Each finding MUST have: title, severity (info|low|medium|high|critical), ' +
                'confidence (low|medium|high), category, description, evidence, impact, remediation. ' +
                'Do not fabricate findings unsupported by the evidence. Use confidence=low when uncertain.',
            },
          ],
        },
      ],
    });

    const text = response.content
      .filter((block) => block.type === 'text')
      .map((b) => b.text ?? '')
      .join('\n')
      .trim();

    return extractJson(text);
  }
}

interface AnthropicLike {
  messages: {
    create: (req: unknown) => Promise<{
      content: Array<{ type: string; text?: string }>;
    }>;
  };
}

/**
 * Pull the first JSON object out of an LLM response. Real models sometimes add
 * surrounding prose even when asked not to.
 */
function extractJson(text: string): string {
  const fenced = text.match(/```json\s*([\s\S]*?)```/i);
  if (fenced && fenced[1]) return fenced[1].trim();
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start >= 0 && end > start) return text.slice(start, end + 1);
  return '{"findings":[]}';
}
