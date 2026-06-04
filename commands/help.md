---
description: Show how to use the security-mcp plugin
---

Print the following help text verbatim to the user, then stop:

```
security-mcp — authorized security testing for localhost + staging only

Commands
  /security-mcp:audit <url> [maxIterations]
      Autonomous EXPERT audit: you act as a 20-yr offensive-security lead.
      Maps the full attack surface, probes every applicable goal until
      coverage is satisfied, and prints the full report INLINE in the thread
      (attack-surface map + goal-coverage matrix + attack-chain findings +
      prioritized remediation). Non-destructive; localhost/staging only.

  /security-mcp:audit-team <url> [maxIterations] [--account role=..,token=..]
      DEEP multi-agent audit: a manager does shared setup once (discover +
      acquire identity), then fans out specialist sub-agents (one per breach
      class: access-control, auth, injection, SSRF/internal, data/cloud-storage,
      database, config/business-logic) in PARALLEL and synthesizes one report.
      More thorough + reliable than /audit, but costs more tokens. Use for
      serious, no-stone-unturned audits. Non-destructive; localhost/staging only.

  /security-mcp:scan <url> [quick|standard|deep]
      Full scan: validate → crawl → multi-role probe → prompt loop → write report

  /security-mcp:validate <url>
      Policy check only. Returns allowed / blocked with reason.

  /security-mcp:loop <url> [single-pass|iterative]
      Re-run the prompt loop against existing evidence (no new crawl).

  /security-mcp:report <url>
      Generate Markdown + JSON report from supplied findings + evidence.

  /security-mcp:ralph <url> [scanType] [maxIterations]
      Autonomous iterative scanning via Ralph Loop — keeps exploring new
      attack surface each iteration until coverage is satisfied.

  /security-mcp:help
      Show this message.

Tools (also callable directly by the model)
  validate_target, security_scan, list_security_prompts,
  run_prompt_loop, generate_report

Architecture
  The MCP collects evidence + runs deterministic checks (heuristics,
  active probes, YAML templates). The CALLING LLM (you, when invoked from
  Claude Code) does the security reasoning by fetching prompts via
  list_security_prompts and applying them against scan evidence. The
  server-side LLM client (Anthropic) is OPTIONAL and only used for
  headless / CI contexts via includeServerSidePromptLoop=true.

Allowed targets
  localhost, 127.0.0.1, ::1, hosts in ALLOWED_STAGING_HOSTS env var
  Blocked: anything containing production/prod/live, cloud-metadata IPs,
  private network ranges, unknown public hosts.

Reports
  Written to $REPORTS_DIR (default: plugin's reports/ directory).
  Each scan produces <timestamp>-<host>.md and .json.

Test accounts
  Supply two or more accounts to security_scan to unlock differential
  IDOR / BOLA / tenant-isolation checks. Tokens/cookies are NEVER written
  into reports.
```
