---
description: Run an authorized security scan against a localhost or allowlisted staging URL — YOU do the LLM reasoning, the MCP just collects evidence
argument-hint: <targetUrl> [quick|standard|deep]
---

Run a security scan against the target URL in `$ARGUMENTS`. **You (the calling LLM) are the reasoning engine.** The MCP server only collects evidence and runs deterministic checks — never let it call its own LLM (no `includeServerSidePromptLoop` flag).

Parse arguments:
- First token = `targetUrl` (required)
- Second token = `scanType` (optional, default `standard`, one of: `quick`, `standard`, `deep`)
- Any `--account role=<name>,token=<jwt>` flags = entries for `testAccounts`

Steps you MUST follow in order:

1. Call `validate_target` with `{ "targetUrl": <url> }`. If `allowed: false`, STOP and report the reason.

2. Call `security_scan` with:
   ```json
   {
     "targetUrl": "<url>",
     "scanType": "<quick|standard|deep>",
     "includeActiveProbes": true,
     "includeTemplates": true,
     "testAccounts": [ ...parsed from --account flags... ]
   }
   ```
   This returns deterministic findings from heuristics + active probes + YAML templates, the full `evidence` object, and report paths.

3. Call `list_security_prompts` to fetch the prompt registry (39 modules). You may filter by category if scope is narrow (e.g. `{ "category": "auth" }`).

4. For each returned prompt: read its `prompt` text, apply your own reasoning against the `evidence` returned in step 2, and produce findings WHERE THE EVIDENCE SUPPORTS THEM. Each finding must include: `title`, `severity` (info|low|medium|high|critical), `confidence` (low|medium|high), `category`, `description`, `evidence`, `impact`, `remediation`. Do not invent findings — use `confidence: low` when uncertain.

5. Once you have your own reasoned findings, call `generate_report` with:
   ```json
   {
     "targetUrl": "<url>",
     "scope": ["<localhost|staging>"],
     "findings": [ ...heuristic findings from step 2 + your reasoned findings from step 4... ],
     "evidence": <evidence from step 2>
   }
   ```
   This writes the consolidated Markdown + JSON report.

6. Present to the user:
   - The summary block (total findings, counts by severity, risk level)
   - The top 5 findings by severity (title, severity, confidence, one-line impact)
   - The absolute paths to the generated Markdown and JSON reports
   - One short recommendation: which finding to investigate first and why

Do NOT:
- Set `includeServerSidePromptLoop: true` (wasteful — you are the LLM).
- Invent findings the evidence does not support.
- Claim certainty beyond the `confidence` field.
- Scan any URL `validate_target` rejected.
