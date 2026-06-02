import type { Finding } from '../../types/finding.types.js';
import type { ScanEvidence, TestAccount } from '../../types/scan.types.js';

export interface PromptContext {
  targetUrl: string;
  evidence: ScanEvidence | Record<string, unknown>;
  previousFindings: Finding[];
  testAccounts: TestAccount[];
  iteration: number;
}

export function buildContext(input: {
  targetUrl: string;
  evidence: ScanEvidence | Record<string, unknown>;
  previousFindings?: Finding[];
  testAccounts?: TestAccount[];
  iteration?: number;
}): PromptContext {
  return {
    targetUrl: input.targetUrl,
    evidence: input.evidence,
    previousFindings: input.previousFindings ?? [],
    testAccounts: input.testAccounts ?? [],
    iteration: input.iteration ?? 0,
  };
}
