import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence } from '../../helpers.js';

const SENSITIVE_PATHS = [
  '/.env',
  '/.env.local',
  '/.git/config',
  '/.git/HEAD',
  '/config.json',
  '/composer.lock',
  '/package.json',
  '/swagger.json',
  '/openapi.json',
];

export const envLeakPrompt: SecurityPrompt = {
  id: 'config.env-leak',
  title: 'Environment / config file leakage',
  category: 'configuration',
  severityFocus: 'critical',
  prompt: [
    'Goal: Detect publicly accessible config files (.env, .git/config, dotfiles, lockfiles)',
    'that may leak secrets or dependency information.',
    '',
    'Evidence required: GETs against well-known sensitive paths; response status and any',
    'matched secret-shaped strings (key=value).',
    '',
    'Constraints: only fetch the listed paths once each. Redact captured secrets before storing.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const exposed = ev.pages.filter(
      (p) =>
        SENSITIVE_PATHS.some((sp) => p.finalUrl.endsWith(sp)) &&
        p.status >= 200 &&
        p.status < 300,
    );
    if (exposed.length === 0) return [];
    return [
      {
        title: 'Sensitive config files appear publicly accessible',
        severity: 'critical' as const,
        category: 'configuration',
        description:
          'One or more sensitive files were served with a 2xx status. These commonly contain ' +
          'secrets, internal endpoints or build metadata.',
        evidence: { exposed: exposed.map((p) => ({ url: p.finalUrl, status: p.status })) },
        impact: 'Full system compromise is often possible when .env or .git is exposed.',
        remediation:
          'Block these paths at the web server / CDN layer. Move secrets out of repo. Ensure deploys ' +
          'do not copy dotfiles into the public directory.',
        confidence: 'high' as const,
      },
    ];
  },
};
