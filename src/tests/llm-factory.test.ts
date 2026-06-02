import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createLLMClient } from '../core/prompt-engine/llm-factory.js';
import { resetEnvCacheForTests } from '../config/env.js';
import { MockLLMClient } from '../core/prompt-engine/llm-client.js';

const ORIGINAL = process.env;

beforeEach(() => {
  process.env = { ...ORIGINAL };
  resetEnvCacheForTests();
});

afterEach(() => {
  process.env = ORIGINAL;
  resetEnvCacheForTests();
});

describe('createLLMClient', () => {
  it('returns mock when LLM_PROVIDER is unset', () => {
    delete process.env.LLM_PROVIDER;
    const c = createLLMClient();
    expect(c).toBeInstanceOf(MockLLMClient);
  });

  it('returns mock when LLM_PROVIDER=mock', () => {
    process.env.LLM_PROVIDER = 'mock';
    const c = createLLMClient();
    expect(c).toBeInstanceOf(MockLLMClient);
  });

  it('throws when LLM_PROVIDER=anthropic without key', () => {
    process.env.LLM_PROVIDER = 'anthropic';
    delete process.env.ANTHROPIC_API_KEY;
    expect(() => createLLMClient()).toThrow(/ANTHROPIC_API_KEY/);
  });
});
