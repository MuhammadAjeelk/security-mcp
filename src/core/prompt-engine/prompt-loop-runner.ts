import type { Finding } from '../../types/finding.types.js';
import type { LoopMode, ScanEvidence, TestAccount } from '../../types/scan.types.js';
import type { LLMClient } from './llm-client.js';
import { createLLMClient } from './llm-factory.js';
import { buildContext } from './prompt-context.js';
import { PROMPT_REGISTRY } from './prompt-registry.js';
import type { PromptFinding, SecurityPrompt } from './types.js';
import { getEnv } from '../../config/env.js';

export interface PromptLoopInput {
  targetUrl: string;
  evidence: ScanEvidence | Record<string, unknown>;
  loopMode: LoopMode;
  maxIterations?: number;
  testAccounts?: TestAccount[];
  llmClient?: LLMClient;
  prompts?: readonly SecurityPrompt[];
}

export interface PromptLoopResult {
  iterations: number;
  findings: Finding[];
  stopReason: 'max-iterations' | 'no-new-findings' | 'single-pass-complete';
}

export async function runPromptLoop(input: PromptLoopInput): Promise<PromptLoopResult> {
  const env = getEnv();
  const llm = input.llmClient ?? createLLMClient();
  const prompts = input.prompts ?? PROMPT_REGISTRY;
  const cap =
    input.loopMode === 'single-pass' ? 1 : Math.min(input.maxIterations ?? env.PROMPT_LOOP_MAX_ITERATIONS, 20);

  const findings: Finding[] = [];
  const seenKeys = new Set<string>();

  let iteration = 0;
  let stopReason: PromptLoopResult['stopReason'] = 'max-iterations';

  for (; iteration < cap; iteration++) {
    let newThisIteration = 0;
    for (const prompt of prompts) {
      const ctx = buildContext({
        targetUrl: input.targetUrl,
        evidence: input.evidence,
        previousFindings: findings,
        testAccounts: input.testAccounts,
        iteration,
      });

      const heuristicFindings = prompt.heuristic ? prompt.heuristic(ctx) : [];

      // Always consult the LLM client too — the mock returns an empty array, but
      // a real client can add findings on top of the deterministic baseline.
      const llmRaw = await llm.complete({
        systemPrompt:
          'You are a security tester operating under strict authorized-target rules. Only produce ' +
          'findings backed by the supplied evidence. Output JSON: { findings: [...] }.',
        userPrompt: prompt.prompt,
        evidence: { targetUrl: input.targetUrl, evidence: input.evidence, previousFindings: findings },
      });
      const llmFindings = parseLLMFindings(llmRaw);

      for (const pf of [...heuristicFindings, ...llmFindings]) {
        const finding = toFinding(prompt, pf);
        const key = `${finding.promptId}::${finding.title}`;
        if (seenKeys.has(key)) continue;
        seenKeys.add(key);
        findings.push(finding);
        newThisIteration += 1;
      }
    }

    if (input.loopMode === 'single-pass') {
      stopReason = 'single-pass-complete';
      iteration += 1;
      break;
    }

    if (newThisIteration === 0) {
      stopReason = 'no-new-findings';
      iteration += 1;
      break;
    }
  }

  return { iterations: iteration, findings, stopReason };
}

function toFinding(prompt: SecurityPrompt, pf: PromptFinding): Finding {
  const id = `${prompt.id}::${hash(`${pf.title}|${JSON.stringify(pf.evidence ?? null)}`)}`;
  return {
    id,
    title: pf.title,
    severity: pf.severity,
    category: pf.category,
    description: pf.description,
    evidence: pf.evidence,
    impact: pf.impact,
    remediation: pf.remediation,
    confidence: pf.confidence,
    promptId: prompt.id,
  };
}

function parseLLMFindings(raw: string): PromptFinding[] {
  try {
    const parsed = JSON.parse(raw) as { findings?: PromptFinding[] };
    if (!parsed || !Array.isArray(parsed.findings)) return [];
    return parsed.findings.filter(
      (f) => typeof f?.title === 'string' && typeof f?.severity === 'string',
    );
  } catch {
    return [];
  }
}

function hash(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (h * 31 + s.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(36);
}
