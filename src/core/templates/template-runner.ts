import { request } from 'undici';
import { validateTarget } from '../policy/target-policy.js';
import { evaluateMatcher } from './matchers.js';
import type { SecurityTemplate, TemplateRequest } from './types.js';
import type { Finding } from '../../types/finding.types.js';
import type { AuthSession } from '../../types/scan.types.js';
import { AuditLogger } from '../logging/audit-logger.js';
import { getEnv } from '../../config/env.js';

export interface TemplateRunInput {
  targetUrl: string;
  templates: readonly SecurityTemplate[];
  session?: AuthSession;
  extraAllowedHosts?: string[];
  audit: AuditLogger;
}

export async function runTemplates(input: TemplateRunInput): Promise<Finding[]> {
  const env = getEnv();
  const decision = validateTarget(input.targetUrl, { extraAllowedHosts: input.extraAllowedHosts });
  if (!decision.allowed || !decision.normalizedUrl) {
    throw new Error(`Template run refused: ${decision.reason}`);
  }

  const findings: Finding[] = [];
  let requestBudget = env.SCAN_MAX_REQUESTS;

  input.audit.event('templates.start', { templates: input.templates.length });

  for (const tpl of input.templates) {
    if (requestBudget <= 0) break;
    for (const req of tpl.requests) {
      const paths = req.paths ?? ['/'];
      for (const path of paths) {
        if (requestBudget <= 0) break;
        const url = absolute(input.targetUrl, path);
        const reDecision = validateTarget(url, { extraAllowedHosts: input.extraAllowedHosts });
        if (!reDecision.allowed) {
          input.audit.event('templates.skip', { url, reason: reDecision.reason });
          continue;
        }
        requestBudget -= 1;
        try {
          const outcome = await issue(url, req, input.session, env.SCAN_TIMEOUT_MS);
          const matched = checkMatchers(req, outcome);
          if (matched) {
            findings.push(buildFinding(tpl, url, outcome));
          }
        } catch (err) {
          input.audit.event('templates.error', {
            templateId: tpl.id,
            url,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
    }
  }

  input.audit.event('templates.done', { findings: findings.length });
  return findings;
}

function absolute(base: string, path: string): string {
  try {
    return new URL(path, base).toString();
  } catch {
    return base;
  }
}

interface IssueOutcome {
  status: number;
  headers: Record<string, string>;
  body: string;
}

async function issue(
  url: string,
  req: TemplateRequest,
  session: AuthSession | undefined,
  timeoutMs: number,
): Promise<IssueOutcome> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers: Record<string, string> = {
      'user-agent': 'security-mcp/0.2 (+authorized-testing-only)',
      ...(req.headers ?? {}),
    };
    if (session?.bearerToken) headers['authorization'] = `Bearer ${session.bearerToken}`;
    if (session?.cookies) {
      headers['cookie'] = Object.entries(session.cookies).map(([k, v]) => `${k}=${v}`).join('; ');
    }
    const method = (req.method ?? 'GET').toUpperCase() as 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';
    const response = await request(url, {
      method,
      headers,
      body: req.body,
      signal: controller.signal,
      maxRedirections: 0,
    });
    const body = await response.body.text();
    const flat: Record<string, string> = {};
    for (const [k, v] of Object.entries(response.headers)) {
      if (v === undefined) continue;
      flat[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
    }
    return { status: response.statusCode, headers: flat, body: body.slice(0, 128 * 1024) };
  } finally {
    clearTimeout(timer);
  }
}

function checkMatchers(req: TemplateRequest, outcome: IssueOutcome): boolean {
  const results = req.matchers.map((m) => evaluateMatcher(m, outcome));
  const cond = req.matchersCondition ?? 'or';
  return cond === 'and' ? results.every((r) => r.matched) : results.some((r) => r.matched);
}

function buildFinding(tpl: SecurityTemplate, url: string, outcome: IssueOutcome): Finding {
  return {
    id: `template.${tpl.id}.${shortHash(url)}`,
    title: `Template match: ${tpl.info.name}`,
    severity: tpl.info.severity,
    category: tpl.info.tags?.[0] ?? 'template',
    description: tpl.info.description ?? `Template ${tpl.id} matched at ${url}`,
    evidence: {
      templateId: tpl.id,
      url,
      status: outcome.status,
      headers: pick(outcome.headers, [
        'server',
        'content-type',
        'x-powered-by',
        'set-cookie',
        'location',
      ]),
      bodySnippet: outcome.body.slice(0, 400),
    },
    impact: tpl.info.description ?? 'See template metadata.',
    remediation:
      tpl.info.reference?.[0]
        ? `Review the referenced advisory: ${tpl.info.reference[0]}`
        : 'Audit the matched endpoint, lock down access, and patch.',
    confidence: tpl.confidence ?? 'medium',
    promptId: `template.${tpl.id}`,
  };
}

function pick(obj: Record<string, string>, keys: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of keys) {
    if (obj[k] !== undefined) out[k] = obj[k]!;
  }
  return out;
}

function shortHash(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
}
