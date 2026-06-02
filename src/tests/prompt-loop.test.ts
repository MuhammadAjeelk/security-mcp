import { describe, expect, it } from 'vitest';
import { runPromptLoop } from '../core/prompt-engine/prompt-loop-runner.js';
import type { SecurityPrompt } from '../core/prompt-engine/types.js';

function staticPrompt(id: string, title: string): SecurityPrompt {
  return {
    id,
    title,
    category: 'headers',
    severityFocus: 'low',
    prompt: 'noop',
    heuristic: () => [
      {
        title,
        severity: 'low',
        category: 'headers',
        description: 'test',
        evidence: { id },
        impact: 'test',
        remediation: 'test',
        confidence: 'low',
      },
    ],
  };
}

function noFindingsPrompt(id: string): SecurityPrompt {
  return {
    id,
    title: 'noop',
    category: 'headers',
    severityFocus: 'low',
    prompt: 'noop',
    heuristic: () => [],
  };
}

describe('runPromptLoop', () => {
  it('stops after one pass in single-pass mode', async () => {
    const r = await runPromptLoop({
      targetUrl: 'http://localhost/',
      evidence: {},
      loopMode: 'single-pass',
      prompts: [staticPrompt('a', 'A'), staticPrompt('b', 'B')],
    });
    expect(r.iterations).toBe(1);
    expect(r.stopReason).toBe('single-pass-complete');
    expect(r.findings).toHaveLength(2);
  });

  it('terminates iterative mode when no new findings appear', async () => {
    const r = await runPromptLoop({
      targetUrl: 'http://localhost/',
      evidence: {},
      loopMode: 'iterative',
      maxIterations: 5,
      prompts: [staticPrompt('a', 'A')],
    });
    // First iteration produces a finding; second produces a duplicate that gets
    // deduped — stop signal fires.
    expect(r.stopReason).toBe('no-new-findings');
    expect(r.iterations).toBeLessThanOrEqual(2);
    expect(r.findings).toHaveLength(1);
  });

  it('respects maxIterations cap', async () => {
    // A prompt that always emits a NEW unique finding each iteration via the
    // iteration counter would normally run forever; we cap at maxIterations=2.
    const ctr = { n: 0 };
    const churning: SecurityPrompt = {
      id: 'churn',
      title: 'churn',
      category: 'headers',
      severityFocus: 'low',
      prompt: 'noop',
      heuristic: () => {
        ctr.n += 1;
        return [
          {
            title: `Finding-${ctr.n}`,
            severity: 'low',
            category: 'headers',
            description: 'x',
            evidence: { n: ctr.n },
            impact: 'x',
            remediation: 'x',
            confidence: 'low',
          },
        ];
      },
    };
    const r = await runPromptLoop({
      targetUrl: 'http://localhost/',
      evidence: {},
      loopMode: 'iterative',
      maxIterations: 2,
      prompts: [churning],
    });
    expect(r.iterations).toBe(2);
    expect(r.stopReason).toBe('max-iterations');
    expect(r.findings).toHaveLength(2);
  });

  it('returns empty findings when all prompts are silent', async () => {
    const r = await runPromptLoop({
      targetUrl: 'http://localhost/',
      evidence: {},
      loopMode: 'iterative',
      maxIterations: 3,
      prompts: [noFindingsPrompt('a')],
    });
    expect(r.findings).toHaveLength(0);
    expect(r.stopReason).toBe('no-new-findings');
  });
});
