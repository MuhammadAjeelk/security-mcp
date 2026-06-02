import type { SecurityPrompt } from '../../types.js';

export const sqlInjectionPrompt: SecurityPrompt = {
  id: 'injection.sql',
  title: 'SQL injection surface review',
  category: 'injection',
  severityFocus: 'critical',
  prompt: [
    'Goal: Identify endpoints likely vulnerable to SQLi: unparameterized queries, error-based',
    'leakage in responses, ORDER BY/limit/raw filters.',
    '',
    'Evidence required: query-string parameters on discovered endpoints, response bodies that',
    'echo input, error messages mentioning SQL/database engines.',
    '',
    'Constraints: NO destructive payloads. Use only benign markers (e.g. single quote, comment',
    'sequence) to detect parser errors. Never UNION/DROP. Never enumerate data.',
    '',
    'Output: severity high when DB error strings appear with benign markers; confidence medium',
    'without payload confirmation.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = ctx.evidence as { pages?: Array<{ finalUrl: string }>; notes?: string[] };
    const errorRe = /\b(sql|syntax|mysql|postgres|sqlite|odbc|ora-\d+)\b/i;
    const matches = (ev.pages ?? []).filter((p) => errorRe.test(p.finalUrl));
    if (matches.length === 0) return [];
    return [
      {
        title: 'URLs referencing SQL-related paths discovered',
        severity: 'low' as const,
        category: 'injection',
        description: 'URLs containing SQL-related keywords were observed; manually verify parameter handling.',
        evidence: { urls: matches.map((m) => m.finalUrl).slice(0, 5) },
        impact: 'If query parameters reach SQL unsanitized, full database compromise is possible.',
        remediation: 'Use parameterized queries or an ORM. Never interpolate user input into SQL.',
        confidence: 'low' as const,
      },
    ];
  },
};
