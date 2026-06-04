# Specialist playbooks — the 7-agent deep audit

These are the **full task lists** for the specialist sub-agents dispatched by
[`/security-mcp:audit-team`](../../commands/audit-team.md). The manager does shared
setup once (deep `security_scan` + acquire a credential), writes a SHARED BRIEF, then
fans out one specialist per breach class **in parallel**, handing each the path to its
playbook below. Each specialist Reads its playbook and executes the ordered checklist
top-to-bottom, then returns the standard return contract.

Every playbook follows the same shape: **Mission · Inputs from the SHARED BRIEF ·
Weapons (real goal-ids / probers / templates / scan options) · Ordered checklist
(per sub-class, with break signal + pass/fail) · Proof required to claim `clean` ·
Blocked conditions (+ what unblocks) · Return contract.**

The honesty rule from [critical-coverage.md](../critical-coverage.md) governs all of
them: never claim `clean` without the stated proof, never silently skip a sub-test, and
flag every blocked sub-test loudly with exactly what unblocks it.

| # | Specialist | Breach class | Playbook |
|---|-----------|--------------|----------|
| 1 | Access-Control | IDOR/BOLA · priv-esc · BFLA · multi-tenant | [01-access-control.md](01-access-control.md) |
| 2 | Authentication | authn/authz on every route · JWT · sessions · reset/oauth · verification-gate | [02-authentication.md](02-authentication.md) |
| 3 | Injection | SQLi · NoSQLi · cmd · XSS · SSTI · XXE · path-traversal · deserialization | [03-injection.md](03-injection.md) |
| 4 | SSRF & Internal/VPC | SSRF sinks · metadata · internal/actuator exposure | [04-ssrf-internal.md](04-ssrf-internal.md) |
| 5 | Data Exposure & Cloud Storage | S3/GCS/Azure · secrets · excessive/sensitive data · env leak | [05-data-exposure-cloud.md](05-data-exposure-cloud.md) |
| 6 | Database & Infra | exposed consoles · DB creds · DB injection/fingerprint · dependency risk | [06-database-infra.md](06-database-infra.md) |
| 7 | Config / Headers / Business-Logic | headers · CORS/CSRF · debug/introspection · caching · rate-limit · files · payment/coupon/race | [07-config-headers-bizlogic.md](07-config-headers-bizlogic.md) |

Scope is enforced by `validate_target`: these run only against `localhost` or an
allowlisted staging host, under explicit owner authorization. prove-don't-pillage —
confirm control with a minimal read-only proof, then STOP.
