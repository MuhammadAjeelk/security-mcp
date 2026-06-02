---
description: Check whether a URL is allowed under the security-mcp target policy
argument-hint: <targetUrl>
---

Validate the URL in `$ARGUMENTS` against the security-mcp target policy.

Steps:

1. Call the `validate_target` MCP tool with `{ "targetUrl": "$ARGUMENTS" }`.

2. Report:
   - `allowed: true` / `allowed: false`
   - the `reason` string
   - if allowed, the `classification` (`localhost` or `staging`) and `normalizedUrl`
   - if blocked, suggest the closest legitimate alternative (e.g. "use localhost or add `<host>` to ALLOWED_STAGING_HOSTS")

Do not scan anything. This command is policy-only.
