import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence } from '../../helpers.js';

export const dependencyRiskPrompt: SecurityPrompt = {
  id: 'infrastructure.dependency-risk',
  title: 'Exposed dependency / version metadata',
  category: 'infrastructure',
  severityFocus: 'medium',
  prompt: [
    'Goal: Detect public exposure of package.json, composer.json, gemfile.lock or other',
    'dependency manifests that disclose exact versions.',
    '',
    'Evidence required: 2xx responses to common dependency manifest paths.',
    '',
    'Output: severity medium; confidence high when directly fetched.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const manifestPaths = ['/package.json', '/composer.json', '/Gemfile.lock', '/yarn.lock'];
    const exposed = ev.pages.filter(
      (p) => manifestPaths.some((m) => p.finalUrl.endsWith(m)) && p.status === 200,
    );
    if (exposed.length === 0) return [];
    return [
      {
        title: 'Dependency manifest exposed publicly',
        severity: 'medium' as const,
        category: 'infrastructure',
        description:
          'A dependency manifest was served from a public URL. Attackers can map exact versions to known CVEs.',
        evidence: { urls: exposed.map((p) => p.finalUrl) },
        impact: 'Targeted exploitation of known vulnerable versions.',
        remediation: 'Block these paths at the web server / CDN. Do not deploy them as static assets.',
        confidence: 'high' as const,
      },
    ];
  },
};
