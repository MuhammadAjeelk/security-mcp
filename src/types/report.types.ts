import type { Finding, Severity } from './finding.types.js';
import type { ScanEvidence, ScanType } from './scan.types.js';

export interface ReportInput {
  targetUrl: string;
  scope: string[];
  scanType?: ScanType;
  findings: Finding[];
  evidence: ScanEvidence | Record<string, unknown>;
  generatedAt?: string;
}

export interface ReportSummary {
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  riskLevel: Severity;
}

export interface GeneratedReport {
  markdown: string;
  json: SerializedReport;
}

export interface SerializedReport {
  schemaVersion: '1.0';
  title: string;
  targetUrl: string;
  scope: string[];
  scanType?: ScanType;
  generatedAt: string;
  summary: ReportSummary;
  findings: Finding[];
  evidence: ScanEvidence | Record<string, unknown>;
  disclaimer: string;
}
