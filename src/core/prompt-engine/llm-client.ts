export interface LLMCompletionInput {
  systemPrompt: string;
  userPrompt: string;
  evidence: unknown;
}

export interface LLMClient {
  complete(input: LLMCompletionInput): Promise<string>;
}

/**
 * Minimal mock client. Real LLM clients (Anthropic / OpenAI / Bedrock / etc.)
 * can be added by implementing the same interface. The prompt-loop runner
 * does NOT depend on the implementation behind LLMClient.
 */
export class MockLLMClient implements LLMClient {
  async complete(_input: LLMCompletionInput): Promise<string> {
    return JSON.stringify({
      findings: [],
      note: 'mock-llm: no model attached; relying on deterministic heuristics in prompt modules.',
    });
  }
}
