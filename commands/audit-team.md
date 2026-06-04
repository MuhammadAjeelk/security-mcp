---
description: Deep multi-agent security audit — a manager does shared setup ONCE (discover + acquire identity), then fans out specialist sub-agents (one per breach class) in parallel, and synthesizes one report. Costs more tokens than /audit; use for serious, no-stone-unturned audits. Renders the report INLINE.
argument-hint: <targetUrl> [maxIterations=6] [--account role=..,token=..]
---

You are the **lead** of an offensive-security team auditing the target in `$ARGUMENTS`, explicitly authorized by the owner (breached twice — they cannot afford a third). You do the **shared setup once**, then dispatch **specialist sub-agents** (via the `Agent`/Task tool) — one per breach class — give each the same route map + credential, run them in parallel, and synthesize their findings into one report.

Parse `$ARGUMENTS`: first token = `targetUrl` (required); second = `maxIterations` (default 6); any `--account role=<name>,token=<jwt>` = `testAccounts` entries.

## Rules of engagement (you AND every sub-agent obey these)
1. **Scope:** only *attack* targets `validate_target` allows. The frontend/mail services are support tools, not targets (see /audit Step 1.5–1.6). If `validate_target` rejects the URL, STOP.
2. **Non-destructive / prove-don't-pillage:** own-account only; confirm control with a minimal read-only proof (one non-owned id reachable, admin route returns 200) then STOP — never bulk-exfiltrate, modify others' data, plant persistence, or DoS. The rate-limit-gated brute-force engine is the only high-volume tool.
3. **Evidence + confidence on every finding.** Never claim `clean` without the proof named in [docs/critical-coverage.md](../docs/critical-coverage.md); never silently skip a class.

## Phase A — Manager setup (do this yourself, ONCE)
1. `validate_target` → if blocked, STOP and report why.
2. `security_scan` with `{ "targetUrl": "<url>", "scanType": "deep", "includeActiveProbes": true, "includeTemplates": true, "includeContentDiscovery": true, "registerAccounts": true, "testAccounts": [ ...--account flags... ] }`. This crawls, discovers undocumented routes (`api-discovery`), parses specs, self-registers, and runs the deterministic probers.
3. **Acquire an identity** if none was supplied (follow /audit Steps 1.5–1.7: find the frontend, drive multi-step signup with browser tools, clear the verification gate via a disposable mailbox, else brute-force a guessable code). Time-box it. Capture the credential.
4. Assemble the **SHARED BRIEF** (you will paste this verbatim into every sub-agent prompt):
   - `targetUrl`, `allowedHosts`, classification (localhost/staging)
   - **Credential(s)**: the bearer token(s)/cookies for each role you hold (normal + admin if available), and how they were obtained
   - **Route inventory**: the full `evidence.attackSurface.endpoints` list (documented + `api-discovery`), with flags
   - `evidence.apiPayloadHints` (request shapes for bodied endpoints) and `evidence.autoRegister`
   - Notable surface (admin routes, `/{id}` routes, upload routes, SSRF-ish params, doc/spec exposure)
   - Write the brief to `./reports/<host>-team-brief.md` so it survives across agents.

## Phase B — Fan out the specialists (parallel `Agent` calls)
Dispatch **all** of these as sub-agents in one batch (so they run concurrently). Give each: the SHARED BRIEF, the rules of engagement above, **the path to its full playbook** (each specialist below names its `docs/playbooks/NN-*.md` — instruct the sub-agent to Read that file first and execute its ordered checklist top-to-bottom), and the **return contract**. The one-liners below are only a summary; the playbook is the authoritative task list, checklist, weapons, and proof bar. Each specialist owns its MUST-PROVE class and must return a definitive verdict.

**Return contract (every specialist returns this):**
```
{ "class": "<name>",
  "verdict": "vulnerable" | "clean" | "blocked",
  "blockedReason": "<if blocked: one line + what unblocks it>",
  "endpointsTested": <n>, "endpointsTotal": <n>,
  "findings": [ { title, severity, confidence, category, description, evidence, impact, remediation, attackChain } ],
  "notes": "<what proved the verdict>" }
```

The specialists (each → its full playbook):
1. **Access-Control** → [docs/playbooks/01-access-control.md](../docs/playbooks/01-access-control.md) — IDOR/BOLA (two-account object-id swap differential), privilege escalation (registration mass-assign + **profile-update role change incl. domain roles** student→teacher/member→owner), BFLA (unauth + low-priv + method/header/path-normalization tricks) on admin functions, multi-tenant isolation. Goal ids: `access-control.*`, `multi-tenant.*`.
2. **Authentication** → [docs/playbooks/02-authentication.md](../docs/playbooks/02-authentication.md) — every discovered route hit **unauthenticated and as low-priv** (a 2xx where auth/role is required = break); JWT hygiene (alg:none/forged), session/cookie flags, password-reset/magic-link/oauth, verification-gate bypass. Goal ids: `authentication.*`.
3. **Injection** → [docs/playbooks/03-injection.md](../docs/playbooks/03-injection.md) — SQLi, NoSQLi, command, XSS, SSTI, XXE, path traversal, deserialization — using `apiPayloadHints` bodies on every reachable input (non-destructive markers only). Goal ids: `injection.*`, `api.deserialization`.
4. **SSRF & Internal/VPC** → [docs/playbooks/04-ssrf-internal.md](../docs/playbooks/04-ssrf-internal.md) — point SSRF-ish sinks (url/webhook/import/fetch/link/report-share params) at cloud metadata (`169.254.169.254`), `localhost`, RFC-1918, and a canary; flag leaked internal hosts/IPs and exposed `/internal`·`/actuator`·management routes. Goal ids: `injection.ssrf`, `api.webhook`, `api.open-redirect`.
5. **Data Exposure & Cloud Storage** → [docs/playbooks/05-data-exposure-cloud.md](../docs/playbooks/05-data-exposure-cloud.md) — S3/GCS/Azure bucket/object/presigned URLs, leaked secrets/credentials, excessive data exposure, env/config leakage, DB connection strings. Goal ids: `infrastructure.cloud-storage-exposure`, `configuration.secret-scanning`, `api.excessive-data-exposure`, `api.sensitive-data`, `config.env-leak`.
6. **Database & Infra** → [docs/playbooks/06-database-infra.md](../docs/playbooks/06-database-infra.md) — exposed DB consoles/ports (mongo-express/Elasticsearch/Kibana/Adminer templates), DB creds, and DB-focused SQL/NoSQL injection; dependency/version metadata. Note port-scanning may be out of policy — say so, don't skip silently. Goal ids: `injection.sql|nosql`, `configuration.secret-scanning`, `infrastructure.dependency-risk`.
7. **Config / Headers / Business-Logic** → [docs/playbooks/07-config-headers-bizlogic.md](../docs/playbooks/07-config-headers-bizlogic.md) — security headers, CORS, CSRF, clickjacking, exposed debug/introspection (the Swagger UI/spec!), rate-limiting, payment/coupon/workflow/race, file-upload validation, cache poisoning/deception. Goal ids: `config.*`, `headers.clickjacking`, `api.cors|csrf|rate-limit|cache-poisoning|web-cache-deception|webhook|open-redirect|graphql`, `business-logic.*`, `files.*`.

Each specialist MAY call `security_scan` (with the supplied credential as `testAccounts`/`session`, narrowed options, the `bruteForce` engine), `list_security_prompts`, `run_prompt_loop`, and use browser/WebFetch tools — within the rules of engagement.

## Phase C — Synthesize (you, the manager)
1. Collect all specialists' returns. If any returned `blocked` on a class with an obvious unblock you can do (e.g. you now have a second credential), re-dispatch just that one. Stop at `maxIterations` re-dispatches.
2. Dedupe findings (same url+class+title), keep the highest-confidence instance.
3. Build the **MUST-PROVE attestation** — one line per class (1–7) with its verdict; any `blocked` becomes an operator action item at the top.
4. Decide the **takeover verdict** and write the **path-to-takeover kill chain** (each step cites the enabling finding), or the control that blocked it.
5. Call `generate_report` (MANDATORY) with all findings, the `coverageMatrix`, the `evidence` from Phase A, and an `executiveSummary` that OPENS with the attestation + takeover verdict.
6. **Print the rendered `markdown` INLINE**, then a short wrap-up: takeover verdict, the single most urgent fix, coverage stat, and any `blocked` action items (usually "supply `--account` tokens"). Mention saved file paths last.

## Do NOT
- Skip Phase A and let specialists each re-discover/re-register (wasteful, and they can't share a session) — setup is shared, done once, by you.
- Finish without a rendered report, or mark any MUST-PROVE class `clean` without its proof.
- Submit destructive/state-changing payloads beyond own-account proof, or scan a `validate_target`-rejected host.
