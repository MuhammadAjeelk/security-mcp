export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type Confidence = 'low' | 'medium' | 'high';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  evidence: unknown;
  impact: string;
  remediation: string;
  confidence?: Confidence;
  promptId?: string;
  /**
   * Optional attacker's-eye narrative: how this finding would be chained with
   * others to reach a real objective. Populated by the expert-audit flow.
   */
  attackChain?: string;
}

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
