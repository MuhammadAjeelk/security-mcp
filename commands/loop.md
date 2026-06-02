---
description: Re-run the prompt loop against existing evidence (no new crawl)
argument-hint: <targetUrl> [single-pass|iterative]
---

Re-run the security prompt loop against pre-supplied evidence for the target in `$ARGUMENTS`.

Steps:

1. Ask the user (concisely) for the `evidence` JSON if it was not supplied in this conversation. Suggest they paste the `evidence` block from a prior `security_scan` response, or the JSON report file at `./reports/*.json`.

2. Parse `$ARGUMENTS`:
   - First token = `targetUrl`
   - Second token = `loopMode` (default `iterative`, one of: `single-pass`, `iterative`)

3. Call the `run_prompt_loop` MCP tool:
   ```json
   {
     "targetUrl": "<url>",
     "loopMode": "<single-pass|iterative>",
     "evidence": <pasted evidence JSON>
   }
   ```

4. Present the findings the same way `/security-mcp:scan` does (summary + top findings + stop reason).

5. Note: this does NOT write a report. Suggest `/security-mcp:report` if the user wants one.
