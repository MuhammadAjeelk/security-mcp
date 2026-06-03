import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { crawlTarget } from '../../core/scanner/crawler.js';
import { runBrowserChecks } from '../../core/scanner/browser-scanner.js';
import { buildAttackSurface } from '../../core/scanner/attack-surface.js';
import { runActiveProbes } from '../../core/scanner/probe-runner.js';
import { autoRegister } from '../../core/scanner/auto-register.js';
import { findApiPayload } from '../../core/scanner/api-payload-finder.js';
import { probeAccessControl } from '../../core/scanner/access-control-prober.js';
import { runTemplates } from '../../core/templates/template-runner.js';
import { loadBundledTemplates } from '../../core/templates/template-loader.js';
import { AuditLogger } from '../../core/logging/audit-logger.js';
import { runPromptLoop } from '../../core/prompt-engine/prompt-loop-runner.js';
import { buildAndWriteReport } from '../../core/reports/report-writer.js';
import { validateTarget } from '../../core/policy/target-policy.js';
import type { Finding } from '../../types/finding.types.js';
import type { ScanRequest } from '../../types/scan.types.js';

const TestAccountSchema = z.object({
  role: z.string().min(1),
  email: z.string().optional(),
  token: z.string().optional(),
  cookies: z.record(z.string(), z.string()).optional(),
});

const AuthSessionSchema = z.object({
  cookies: z.record(z.string(), z.string()).optional(),
  bearerToken: z.string().optional(),
  origin: z.string().optional(),
});

export const securityScanInputSchema = z.object({
  targetUrl: z.string().min(1),
  scanType: z.enum(['quick', 'standard', 'deep']),
  maxDepth: z.number().int().min(0).max(10).optional(),
  includeBrowserTests: z.boolean().optional(),
  includeActiveProbes: z.boolean().optional(),
  includeTemplates: z.boolean().optional(),
  includeContentDiscovery: z.boolean().optional(),
  registerAccounts: z.boolean().optional(),
  includeServerSidePromptLoop: z.boolean().optional(),
  session: AuthSessionSchema.optional(),
  allowedHosts: z.array(z.string()).optional(),
  testAccounts: z.array(TestAccountSchema).optional(),
});

export type SecurityScanInput = z.infer<typeof securityScanInputSchema>;

export const securityScanToolDefinition = {
  name: 'security_scan',
  description:
    'Run an authorized security scan against a localhost or allowlisted staging URL. Performs ' +
    'a crawl, optional browser checks, and the full server-side prompt loop, then writes a ' +
    'Markdown + JSON report. Rejects unauthorized targets up front.',
  inputSchema: {
    type: 'object',
    properties: {
      targetUrl: { type: 'string' },
      scanType: { type: 'string', enum: ['quick', 'standard', 'deep'] },
      maxDepth: { type: 'number', minimum: 0, maximum: 10 },
      includeBrowserTests: { type: 'boolean' },
      includeActiveProbes: {
        type: 'boolean',
        description: 'Run the non-destructive active probe library (SQLi/XSS/CRLF/SSRF markers).',
      },
      includeTemplates: {
        type: 'boolean',
        description: 'Run the bundled Nuclei-style YAML templates against the target.',
      },
      includeContentDiscovery: {
        type: 'boolean',
        description:
          'Brute-force a curated wordlist of high-signal paths/files (admin panels, backups, configs). Default on for deep scans.',
      },
      registerAccounts: {
        type: 'boolean',
        description:
          'Self-register throwaway accounts via the public signup flow and probe for mass-assignment privilege escalation. Own-account only, non-destructive.',
      },
      includeServerSidePromptLoop: {
        type: 'boolean',
        description:
          'Default false. Server-side LLM loop. Leave OFF when called from Claude Code/Cursor — the calling LLM is already the reasoner; use list_security_prompts instead.',
      },
      session: {
        type: 'object',
        properties: {
          cookies: { type: 'object', additionalProperties: { type: 'string' } },
          bearerToken: { type: 'string' },
          origin: { type: 'string' },
        },
      },
      allowedHosts: { type: 'array', items: { type: 'string' } },
      testAccounts: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            role: { type: 'string' },
            email: { type: 'string' },
            token: { type: 'string' },
            cookies: { type: 'object', additionalProperties: { type: 'string' } },
          },
          required: ['role'],
        },
      },
    },
    required: ['targetUrl', 'scanType'],
  } as const,
};

export async function handleSecurityScan(input: SecurityScanInput) {
  const decision = validateTarget(input.targetUrl, { extraAllowedHosts: input.allowedHosts });
  if (!decision.allowed) {
    return {
      ok: false as const,
      stage: 'validation' as const,
      reason: decision.reason,
    };
  }

  const scanId = randomUUID();
  const audit = new AuditLogger(scanId);
  audit.event('scan.start', {
    targetUrl: input.targetUrl,
    scanType: input.scanType,
    accounts: input.testAccounts?.length ?? 0,
  });

  const request: ScanRequest = input;
  let evidence = await crawlTarget({ request, audit });
  evidence = await runBrowserChecks(request, evidence, audit);

  // Deterministic attack-surface map — drives the expert-audit coverage flow
  // and the report's surface/coverage sections.
  evidence.attackSurface = buildAttackSurface(evidence);
  audit.event('attack-surface.built', {
    endpoints: evidence.attackSurface.totalEndpoints,
    authGated: evidence.attackSurface.authGated,
    uploads: evidence.attackSurface.uploads,
  });

  const extraFindings: Finding[] = [];

  // Self-registration + self-healing identity + mass-assignment escalation probe.
  if (input.registerAccounts) {
    const reg = await autoRegister({
      evidence,
      extraAllowedHosts: input.allowedHosts,
      audit,
    });
    evidence.autoRegister = reg;
    if (reg.privilegeEscalation) {
      extraFindings.push({
        id: `auto-register.privilege-escalation`,
        title: 'Mass-assignment privilege escalation at signup',
        severity: 'critical',
        category: 'access-control',
        description:
          `The public registration endpoint (${reg.signupUrl}) honored the privilege-bearing ` +
          `field "${reg.privilegeEscalation.field}=${reg.privilegeEscalation.value}" that the ` +
          `signup form never advertised. An unauthenticated attacker can mint an admin account.`,
        evidence: { signupUrl: reg.signupUrl, ...reg.privilegeEscalation },
        impact: 'Unauthenticated full-admin account creation → complete application compromise.',
        remediation:
          'Allowlist the fields accepted at registration server-side. Never bind request bodies ' +
          'directly to privileged user attributes (role, is_admin, permissions).',
        confidence: 'high',
        promptId: 'access-control.role-escalation',
        attackChain:
          'Anonymous attacker POSTs role=admin to /register → server mass-assigns it → ' +
          'attacker logs in as admin → full data access and account takeover.',
      });
    }
    audit.event('auto-register.done', {
      signupFound: reg.signupFound,
      accounts: reg.accounts.length,
      escalation: !!reg.privilegeEscalation,
    });
  }

  // API payload discovery — infer the request shape of bodied API endpoints so
  // downstream checks can actually exercise them. Capped to a small subset.
  if (input.registerAccounts || input.includeActiveProbes) {
    const apiTargets = (evidence.attackSurface?.endpoints ?? [])
      .filter((e) => e.isApiLike && /^(POST|PUT|PATCH)$/i.test(e.method))
      .slice(0, 5);
    if (apiTargets.length > 0) {
      const hints = [];
      for (const t of apiTargets) {
        try {
          const found = await findApiPayload({
            url: t.url,
            method: t.method,
            session: input.session,
            account: input.testAccounts?.[0],
            extraAllowedHosts: input.allowedHosts,
            audit,
          });
          hints.push({
            url: found.url,
            method: found.method,
            encoding: found.encoding,
            requiredFields: found.requiredFields,
            inferredPayload: found.inferredPayload,
            finalStatus: found.finalStatus,
            succeeded: found.succeeded,
          });
        } catch (err) {
          audit.event('payload-finder.error', {
            url: t.url,
            reason: err instanceof Error ? err.message : String(err),
          });
        }
      }
      if (hints.length > 0) evidence.apiPayloadHints = hints;
    }
  }

  // BFLA / access-control prober — replays attacker auth-bypass techniques
  // (unauthenticated access, header tricks, cross-role differential) against
  // admin/auth-gated routes, READ-ONLY.
  if (input.registerAccounts || input.includeActiveProbes) {
    const surfaceEndpoints = evidence.attackSurface?.endpoints ?? [];
    if (surfaceEndpoints.some((e) => e.looksAdmin || e.authGated)) {
      const bflaFindings = await probeAccessControl({
        endpoints: surfaceEndpoints,
        accounts: input.testAccounts,
        extraAllowedHosts: input.allowedHosts,
        audit,
      });
      extraFindings.push(...bflaFindings);
    }
  }

  if (input.includeActiveProbes) {
    const probeFindings = await runActiveProbes({
      endpoints: evidence.endpoints,
      account: input.testAccounts?.[0],
      extraAllowedHosts: input.allowedHosts,
      audit,
    });
    extraFindings.push(...probeFindings);
  }

  if (input.includeTemplates) {
    const templates = await loadBundledTemplates();
    audit.event('templates.loaded', { count: templates.length });
    const tplFindings = await runTemplates({
      targetUrl: input.targetUrl,
      templates,
      session: input.session,
      extraAllowedHosts: input.allowedHosts,
      audit,
    });
    extraFindings.push(...tplFindings);
  }

  // Heuristics in prompt modules are deterministic — run them as a single pass
  // through the Mock client (no LLM call, just heuristic output).
  const heuristicLoop = await runPromptLoop({
    targetUrl: input.targetUrl,
    evidence,
    loopMode: 'single-pass',
    testAccounts: input.testAccounts,
  });

  // Only invoke the real LLM-backed iterative loop when explicitly opted into.
  const llmLoop = input.includeServerSidePromptLoop
    ? await runPromptLoop({
        targetUrl: input.targetUrl,
        evidence,
        loopMode: 'iterative',
        testAccounts: input.testAccounts,
      })
    : null;

  const allFindings: Finding[] = [
    ...extraFindings,
    ...heuristicLoop.findings,
    ...(llmLoop?.findings.filter((f) => !heuristicLoop.findings.some((h) => h.id === f.id)) ?? []),
  ];

  const written = await buildAndWriteReport({
    targetUrl: input.targetUrl,
    scope: [decision.classification ?? 'unknown'],
    scanType: input.scanType,
    findings: allFindings,
    evidence,
  });

  audit.event('scan.done', {
    findings: allFindings.length,
    iterations: llmLoop?.iterations ?? heuristicLoop.iterations,
    stopReason: llmLoop?.stopReason ?? heuristicLoop.stopReason,
    llmLoopUsed: !!llmLoop,
  });

  return {
    ok: true as const,
    scanId,
    summary: written.report.json.summary,
    evidence,
    iterations: llmLoop?.iterations ?? heuristicLoop.iterations,
    stopReason: llmLoop?.stopReason ?? heuristicLoop.stopReason,
    reportPaths: written.paths,
    findings: allFindings,
    nextStep:
      'For deeper reasoning, call list_security_prompts to fetch the prompt library, apply each against the returned evidence, and submit any additional findings via generate_report.',
  };
}
