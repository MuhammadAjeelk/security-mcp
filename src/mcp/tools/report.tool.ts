import { z } from 'zod';
import { buildAndWriteReport } from '../../core/reports/report-writer.js';
import type { Finding } from '../../types/finding.types.js';

const FindingSchema = z.object({
  id: z.string(),
  title: z.string(),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
  category: z.string(),
  description: z.string(),
  evidence: z.unknown(),
  impact: z.string(),
  remediation: z.string(),
  confidence: z.enum(['low', 'medium', 'high']).optional(),
  promptId: z.string().optional(),
  attackChain: z.string().optional(),
});

const CoverageRowSchema = z.object({
  goalId: z.string(),
  goalTitle: z.string().optional(),
  status: z.enum(['clean', 'vulnerable', 'partial', 'not-applicable', 'not-tested']),
  endpointsTested: z.number().int().min(0).optional(),
  endpointsTotal: z.number().int().min(0).optional(),
  endpoints: z.array(z.string()).optional(),
  note: z.string().optional(),
});

export const reportInputSchema = z.object({
  targetUrl: z.string().min(1),
  findings: z.array(FindingSchema),
  evidence: z.record(z.unknown()),
  scope: z.array(z.string()).optional(),
  coverageMatrix: z.array(CoverageRowSchema).optional(),
  executiveSummary: z.string().optional(),
});

export type ReportInputBody = z.infer<typeof reportInputSchema>;

export const reportToolDefinition = {
  name: 'generate_report',
  description:
    'Generate a Markdown + JSON security report from supplied findings and evidence. Writes ' +
    'both files to REPORTS_DIR and returns their paths plus the rendered markdown.',
  inputSchema: {
    type: 'object',
    properties: {
      targetUrl: { type: 'string' },
      findings: { type: 'array', items: { type: 'object' } },
      evidence: { type: 'object' },
      scope: { type: 'array', items: { type: 'string' } },
      coverageMatrix: {
        type: 'array',
        description:
          'Optional goal-coverage matrix from an expert audit. One row per security goal: ' +
          '{ goalId, goalTitle?, status: clean|vulnerable|partial|not-applicable|not-tested, ' +
          'endpointsTested?, endpointsTotal?, endpoints?, note? }.',
        items: { type: 'object' },
      },
      executiveSummary: {
        type: 'string',
        description: 'Optional executive "are we safe now" narrative from an expert audit.',
      },
    },
    required: ['targetUrl', 'findings', 'evidence'],
  } as const,
};

export async function handleGenerateReport(input: ReportInputBody) {
  const written = await buildAndWriteReport({
    targetUrl: input.targetUrl,
    scope: input.scope ?? [],
    findings: input.findings as Finding[],
    evidence: input.evidence,
    coverageMatrix: input.coverageMatrix,
    executiveSummary: input.executiveSummary,
  });
  return {
    ok: true as const,
    paths: written.paths,
    summary: written.report.json.summary,
    markdown: written.report.markdown,
  };
}
