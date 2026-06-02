import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence } from '../../helpers.js';

const DEBUG_PATHS = [
  '/debug',
  '/__debug__',
  '/actuator',
  '/actuator/env',
  '/health',
  '/metrics',
  '/phpinfo.php',
  '/server-status',
];

export const debugEndpointPrompt: SecurityPrompt = {
  id: 'config.debug-endpoint',
  title: 'Exposed debug / introspection endpoints',
  category: 'configuration',
  severityFocus: 'high',
  prompt: [
    'Goal: Detect debug/introspection endpoints (Spring actuator, Django debug toolbar, Flask',
    'debugger, phpinfo) that should not be reachable outside the cluster.',
    '',
    'Evidence required: status of well-known paths; response body indicators ("Werkzeug",',
    '"WhiteLabel", "phpinfo", "Bean").',
    '',
    'Constraints: only fetch the listed paths once each.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const exposed = ev.pages.filter(
      (p) => DEBUG_PATHS.some((d) => p.finalUrl.includes(d)) && p.status >= 200 && p.status < 300,
    );
    if (exposed.length === 0) return [];
    return [
      {
        title: 'Debug or introspection endpoints reachable',
        severity: 'high' as const,
        category: 'configuration',
        description: 'Discovered debug-style endpoints returning 2xx.',
        evidence: { exposed: exposed.map((p) => ({ url: p.finalUrl, status: p.status })) },
        impact:
          'Debug endpoints often leak env vars, beans, route maps, memory usage, or enable arbitrary code execution.',
        remediation:
          'Disable in non-local environments. Bind to a private network. Add an auth boundary.',
        confidence: 'high' as const,
      },
    ];
  },
};
