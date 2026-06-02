---
description: Generate a Markdown + JSON security report from supplied findings and evidence
argument-hint: <targetUrl>
---

Generate a report for the target URL in `$ARGUMENTS`.

Steps:

1. Confirm with the user that you have `findings` and `evidence` available in the conversation. If not, ask them to paste either the previous tool response or point to a JSON report path.

2. Call the `generate_report` MCP tool:
   ```json
   {
     "targetUrl": "<url>",
     "scope": ["localhost"],
     "findings": [ ... ],
     "evidence": { ... }
   }
   ```

3. Report back:
   - The absolute path of the generated `.md` and `.json` files
   - The summary block
   - One-line risk verdict
