---
description: Autonomous iterative security testing — Ralph Loop wraps security_scan to keep probing new attack surface until coverage is satisfied
argument-hint: <targetUrl> [scanType=standard] [maxIterations=5]
---

Kick off an autonomous Ralph Loop that drives security-mcp through repeated scans of $ARGUMENTS, exploring deeper attack surface each iteration, until coverage is satisfied or the iteration cap is hit.

Parse `$ARGUMENTS`:
- First token = `targetUrl` (required)
- Second token = `scanType` (optional, default `standard`)
- Third token = `maxIterations` (optional, default `5`)

Hand off to the Ralph Loop plugin with the prompt below. Use `--completion-promise "SECURITY_SCAN_COMPLETE"` and the parsed `maxIterations`. The Ralph Loop will repeatedly invoke this exact prompt; each iteration Claude sees the report files from prior iterations and decides what to investigate next.

Invoke `/ralph-loop` with the following body as the prompt (substitute the parsed values into `<TARGET>`, `<SCAN_TYPE>`, `<MAX_ITERATIONS>`):

```
You are running an authorized security audit of <TARGET> via the security-mcp plugin.

RULES (non-negotiable):
- Only act within the security-mcp target policy. If validate_target rejects a URL, STOP.
- Read-only / non-destructive probing only. NEVER submit destructive payloads.
- Always emit severity + confidence on every finding. NEVER claim certainty without evidence.
- Each iteration, write a one-line summary to ./reports/ralph-progress.md so future iterations see what's already been done.

ITERATION GOAL:
On each iteration, do exactly one productive thing:

1. If this is the first iteration: call security_scan with
   { targetUrl: "<TARGET>", scanType: "<SCAN_TYPE>", includeActiveProbes: true, includeTemplates: true }.
   Read the resulting Markdown report. Append a short bullet list of the top findings to ./reports/ralph-progress.md.

2. If reports already exist: read ./reports/ralph-progress.md and the most recent .md report. Identify ONE category of attack surface that is under-tested. Examples:
   - We haven't tried authenticated probing -> run security_scan again with testAccounts
   - The crawler didn't reach /api/v1 -> run security_scan with maxDepth=4
   - No templates matched -> run security_scan with includeTemplates and a deeper crawl
   - Specific endpoints look interesting -> use run_prompt_loop with prior evidence and loopMode=iterative
   - Findings need confirmation -> use the generate_report tool to consolidate

   Execute that ONE focused step. Append a short summary to ralph-progress.md.

STOP CONDITIONS:
Emit <promise>SECURITY_SCAN_COMPLETE</promise> when ANY of these is true:
- The last 2 iterations produced no new findings AND no new attack surface to explore.
- ./reports/ralph-progress.md shows >= 4 distinct iteration angles already tried (auth, deep crawl, templates, probes).
- Total findings >= 30 (diminishing returns — write a final consolidated report).
- You have produced a final consolidated Markdown report covering: validated scope, methodology used per iteration, all findings grouped by severity, and a developer remediation checklist.

DO NOT emit the promise just because one iteration completed. Only emit it when coverage is genuinely satisfied.

Output for this iteration:
- One short paragraph: what I'm investigating and why
- The MCP tool calls and a 3-5 bullet result summary
- One line: what the NEXT iteration should try, or the completion promise
```

After kicking off `/ralph-loop`, do not run any tools yourself in this turn — Ralph will re-invoke the prompt above on each loop iteration.
