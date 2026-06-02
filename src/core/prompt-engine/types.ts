import type { Confidence, Finding, Severity } from '../../types/finding.types.js';
import type { PromptContext } from './prompt-context.js';

export type PromptCategory =
  | 'headers'
  | 'auth'
  | 'authorization'
  | 'api'
  | 'access-control'
  | 'input-validation'
  | 'injection'
  | 'business-logic'
  | 'payment'
  | 'files'
  | 'infrastructure'
  | 'configuration'
  | 'multi-tenant'
  | 'reporting';

export interface SecurityPrompt {
  id: string;
  title: string;
  category: PromptCategory;
  severityFocus: Severity;
  /**
   * Free-form text describing the test, what evidence is required, and the
   * structured finding format. Used as the user-prompt body when calling the
   * LLM client.
   */
  prompt: string;
  /**
   * Optional deterministic heuristic that produces findings directly from
   * evidence without an LLM call. Used by the MockLLMClient and can be
   * composed with real LLM output once a real client is plugged in.
   */
  heuristic?: (ctx: PromptContext) => PromptFinding[];
}

/**
 * A finding as emitted by a prompt module. Severity and confidence are
 * always required so we never claim certainty we don't have.
 */
export interface PromptFinding extends Omit<Finding, 'id' | 'promptId' | 'confidence'> {
  confidence: Confidence;
}
