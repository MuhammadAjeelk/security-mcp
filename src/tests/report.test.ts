import { describe, expect, it } from 'vitest';
import { buildJsonReport, summarize, highestSeverity } from '../core/reports/json-report.js';
import { buildMarkdownReport } from '../core/reports/markdown-report.js';
import type { Finding } from '../types/finding.types.js';

const sample: Finding[] = [
  {
    id: 'f1',
    title: 'Missing CSP',
    severity: 'medium',
    category: 'headers',
    description: 'No CSP header',
    impact: 'XSS more impactful',
    remediation: 'Add CSP',
    evidence: { url: 'http://localhost/' },
    confidence: 'high',
  },
  {
    id: 'f2',
    title: 'Exposed .env',
    severity: 'critical',
    category: 'configuration',
    description: '.env returned 200',
    impact: 'Secrets',
    remediation: 'Block in nginx',
    evidence: { url: 'http://localhost/.env' },
    confidence: 'high',
  },
  {
    id: 'f3',
    title: 'X-Powered-By present',
    severity: 'low',
    category: 'configuration',
    description: 'Discloses framework',
    impact: 'Aids attacker',
    remediation: 'Strip header',
    evidence: { x: 1 },
    confidence: 'high',
  },
];

describe('json report', () => {
  it('summarises by severity and picks the highest risk', () => {
    const s = summarize(sample);
    expect(s.totalFindings).toBe(3);
    expect(s.bySeverity.critical).toBe(1);
    expect(s.bySeverity.medium).toBe(1);
    expect(s.bySeverity.low).toBe(1);
    expect(s.riskLevel).toBe('critical');
  });

  it('returns info when no findings', () => {
    expect(highestSeverity([])).toBe('info');
  });

  it('builds a v1 schema with disclaimer', () => {
    const r = buildJsonReport({
      targetUrl: 'http://localhost/',
      scope: ['localhost'],
      findings: sample,
      evidence: {},
    });
    expect(r.schemaVersion).toBe('1.0');
    expect(r.disclaimer).toMatch(/authorized localhost/i);
    // findings are sorted high-severity first
    expect(r.findings[0]!.severity).toBe('critical');
  });
});

describe('markdown report', () => {
  it('renders title, target, summary table, findings and checklist', () => {
    const md = buildMarkdownReport({
      targetUrl: 'http://localhost:3000/',
      scope: ['localhost'],
      findings: sample,
      evidence: {},
    });
    expect(md).toMatch(/# Security review/);
    expect(md).toMatch(/Target URL/);
    expect(md).toMatch(/Overall risk:\*\* \*\*CRITICAL\*\*/);
    expect(md).toMatch(/Developer checklist/);
    expect(md).toMatch(/Disclaimer/);
    expect(md).toMatch(/Exposed \.env/);
  });

  it('handles empty findings gracefully', () => {
    const md = buildMarkdownReport({
      targetUrl: 'http://localhost/',
      scope: ['localhost'],
      findings: [],
      evidence: {},
    });
    expect(md).toMatch(/No findings produced/);
  });
});
