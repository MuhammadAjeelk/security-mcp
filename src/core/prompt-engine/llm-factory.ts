import type { LLMClient } from './llm-client.js';
import { MockLLMClient } from './llm-client.js';
import { AnthropicLLMClient } from './anthropic-llm-client.js';
import { getEnv } from '../../config/env.js';

/**
 * Lazily-resolve an LLMClient based on env. Throws if the configured provider
 * cannot be constructed (e.g. missing API key) — we want loud failure rather
 * than silent fallback to the mock.
 */
export function createLLMClient(): LLMClient {
  const env = getEnv();
  switch (env.LLM_PROVIDER) {
    case 'anthropic':
      return new AnthropicLLMClient();
    case 'mock':
    default:
      return new MockLLMClient();
  }
}
