# Playbook 04 — SSRF & Internal / VPC Exposure

**Mission.** You are Specialist #4 in a `/security-mcp:audit-team <url>` fan-out.
The manager has already done shared setup (discovery + identity acquisition) and
handed you the SHARED BRIEF. Your one breach class: **server-side request forgery
and internal/VPC exposure**. Find every sink where the app fetches a URL you
control, point it at internal targets, and *prove* with fetch/DNS evidence to a
canary whether the app reaches places it must not — then **stop**. Also sweep for
internal hostnames/IPs and exposed management routes leaking in responses or spec.

Honesty rule (from [critical-coverage.md](../critical-coverage.md) class 4): never
return `clean` without the proof below; never skip a sink silently; anything you
can't run is `blocked` with the exact unblock. **prove-don't-pillage** — once a
sink demonstrably reaches an internal target (canary hit, or a 200 with metadata),
record the evidence and STOP. Do not pivot into other internal services, do not
exfiltrate metadata credentials beyond the minimal proof string.

---

## Inputs from the SHARED BRIEF

- **Route inventory + notable surface** — the documented + discovered routes, and
  the brief's pre-flagged SSRF-ish params:
  `url / webhook / import / fetch / link / report-share / callback / image-url /
  pdf / screenshot`. These are your seed sinks.
- **evidence.apiPayloadHints** — inferred body shapes / field names per route; use
  these to construct valid requests so a sink actually fires instead of 400-ing on
  schema validation.
- **Credential(s)** — the identity (session / testAccounts) the manager acquired.
  Many sinks are auth-gated; pass this in `security_scan.session` /
  `testAccounts[]` so authenticated sinks are reachable.
- **Canary host** — if the brief provides an out-of-band canary (Interactsh-style
  domain / IP you control), it is your blind-SSRF oracle. If none is provided, see
  **Blocked conditions**.

---

## Weapons

- **`injection.ssrf`** (`run_prompt_loop` goal) — primary engine: drives controlled
  URLs into candidate sinks and reasons about responses for SSRF signal.
- **`api.webhook`** — webhook-registration / callback sinks; the app fetches a URL
  *you* register, the classic blind-SSRF channel. Aim it at the canary.
- **`api.open-redirect`** — SSRF-adjacent: an open redirect on this host (or a
  trusted one) is a *bypass primitive* — chain it to smuggle an internal target
  past an allow-list (see checklist C).
- **`spring-actuator.yaml`** (template) — detects exposed Spring management
  endpoints (`/actuator/**`, `/env`, `/heapdump`, `/mappings`). Run via
  `security_scan` with `includeTemplates: true`.
- **`security_scan` options** — `scanType` for depth; `includeActiveProbes: true`
  to fire payloads; `includeTemplates: true` for spring-actuator and friends;
  `includeContentDiscovery: true` to surface `/internal`, `/actuator`, mgmt routes;
  `session` / `testAccounts[]` to reach auth-gated sinks; `bruteForce[]` only if
  the brief authorizes it.
- **`browser` / `WebFetch`** — manual confirmation of a single sink and to inspect
  raw response bodies/headers for leaked internal hosts.

---

## Ordered checklist

Work top to bottom. Each sub-step states the **exact action**, the **break signal**,
and the **pass/fail**.

### (A) Enumerate SSRF sinks from the route inventory

Grep the route inventory, spec, and `evidence.apiPayloadHints` for param/field
names matching these patterns (case-insensitive, substring):

```
url  uri  webhook  callback  import  fetch  link  report-share
image  image-url  pdf  screenshot  proxy  dest  destination
redirect  redirect_uri  next  return  source  src  target  feed  remote
```

- **Action:** build a sink list — `{ route, method, param/field, auth-required }`.
  Include query params, JSON body fields (from payload hints), and multipart fields.
  Note any sink that takes a *full URL* vs. just a host vs. a path fragment.
- **Break signal (this step):** N/A — this is enumeration.
- **Pass/fail:** PASS = sink list complete and cross-checked against the brief's
  pre-flagged params. If a flagged param isn't in your list, explain why (route
  removed, requires a precondition) — don't drop it silently.

### (B) Point each sink at the internal target set

For **every** sink from (A), drive `injection.ssrf` (and `api.webhook` for
register-a-URL sinks) at each target below, one target per line. Use the canary in
the request so even silent sinks reveal themselves out-of-band.

- **AWS metadata:** `http://169.254.169.254/latest/meta-data/`
  — **break:** a 200 whose body contains `meta-data` keys (e.g. `iam/`,
  `instance-id`, `hostname`). **CRITICAL.** Grab one minimal token of proof
  (e.g. the `instance-id` string), then STOP — do **not** walk
  `iam/security-credentials/` to pull keys.
- **GCP metadata:** `http://metadata.google.internal/computeMetadata/v1/`
  (requires header `Metadata-Flavor: Google`) — **break:** 200 with project/SA
  data. **CRITICAL.** Same minimal-proof rule.
- **Loopback:** `http://localhost/`, `http://127.0.0.1/`, and variants
  `http://127.1/`, `http://0.0.0.0/`, `http://[::1]/` — **break:** a response that
  differs from the public path (open port banner, different status/body, admin UI).
- **RFC-1918:** sweep representative hosts in `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16` (and the canary-resolved gateway if known) — **break:** any
  connection that succeeds / times out *differently* from a bogus public IP
  (timing oracle = internal host exists).
- **Canary host you control:** point the sink at your OOB canary URL/host —
  **break:** an inbound **HTTP fetch or DNS lookup** lands on the canary =
  confirmed **blind SSRF** even when the app returns nothing useful inline.

- **Pass/fail per sink:** FAIL (vulnerable) = any break signal above fires —
  record route, payload, and the canary/metadata evidence. PASS = sink returns
  4xx / fetch-blocked / allow-list rejection for *all* internal targets AND no
  canary hit. Record the response that proves rejection.

### (C) Bypass techniques when naive payloads are filtered

If a sink rejects `169.254.169.254` / `localhost` / `10.x` outright, it has a
filter — try to defeat it before calling the sink safe:

- **Alternate IP encodings of `169.254.169.254`:** decimal `2852039166`,
  octal `0251.0376.0251.0376`, hex `0xA9FEA9FE`, mixed/short forms — **break:** a
  metadata 200 slips through = filter is a string match, CRITICAL.
- **DNS rebinding (note):** if the filter resolves-then-checks but re-resolves at
  fetch time, a rebinding name (public IP → `169.254.169.254` on second lookup)
  bypasses it. If you have a rebinding-capable canary, try it; otherwise **note**
  the gap and flag as needing the rebind oracle (don't claim clean on TOCTOU).
- **Redirect-to-internal (chain `api.open-redirect`):** host a redirect (an open
  redirect found by `api.open-redirect`, or your canary 302) that points the sink
  at the internal target. **break:** sink follows the redirect to metadata/RFC-1918.
- **Alternate schemes (note only):** `file:///etc/passwd`, `gopher://127.0.0.1:6379/`
  — **do not** weaponize; **note** whether the fetcher accepts non-`http(s)` schemes
  (a 200 / different error proves scheme allow-list is missing) and flag.
- **Embedded creds / parser confusion:**
  `http://expected-host@169.254.169.254/`, `http://169.254.169.254#@expected-host/`,
  backslash/whitespace/`%2e` tricks — **break:** the sink fetches the *internal*
  authority because its URL parser disagrees with its allow-list parser.

- **Pass/fail:** FAIL = any bypass reaches an internal target (record the exact
  encoding/chain). PASS = filter holds across all bypasses tried; list which
  bypasses you ran so the verdict is auditable.

### (D) Internal exposure recon (no SSRF sink required)

Even with zero SSRF, the app can leak the internals directly:

- **Action — leaked internal identifiers:** scan response bodies, headers, the spec
  (`/api/docs-json` etc.), and JS bundles for internal hostnames, RFC-1918 IPs,
  `*.internal` / `*.local` / `*.svc.cluster.local`, VPC/subnet/region/account-id
  strings. **break:** any private host/IP or `account-id` / VPC id in
  client-reachable content. **MEDIUM–HIGH** depending on what leaks.
- **Action — management / internal routes:** run `security_scan` with
  `includeTemplates: true` + `includeContentDiscovery: true` to fire
  **`spring-actuator.yaml`** and probe `/actuator/**`, `/internal/**`,
  `/management/**`, `/env`, `/heapdump`, `/metrics`, `/debug`. **break:** any such
  route returns 200 with config/env/heap/route data unauthenticated. `/env` or
  `/heapdump` exposed = **CRITICAL** (creds in heap/env).
- **Action — metadata in errors:** trigger errors (bad input, oversized, wrong
  content-type) and read stack traces for internal hosts, region, account id,
  ARNs. **break:** infra identifiers in error output.

- **Pass/fail:** PASS = no internal identifiers leak anywhere client-reachable AND
  management/internal routes are absent or auth-gated. FAIL = any leak/exposure
  above; record the exact location and snippet.

---

## Proof required to claim clean

Per [critical-coverage.md](../critical-coverage.md) class 4, you may write
`clean` only with all of:

- **SSRF sinks reject internal targets** — for *each* sink in your list, evidence
  (response/error) that it 4xx'd or allow-list-blocked the metadata IP, loopback,
  and RFC-1918 targets, **and** survived the (C) bypasses you ran.
- **Metadata endpoint unreachable via the app** — no 200 from `169.254.169.254`
  or `metadata.google.internal` through any sink, including encodings/redirects.
- **No internal hosts/IPs leak** — bodies, headers, spec, JS, and error paths are
  free of private hosts/IPs and VPC/region/account identifiers.
- **No exposed management/internal routes** — `/actuator`, `/internal`, `/env`,
  `/heapdump`, etc. absent or auth-gated (spring-actuator template green).
- **Blind-SSRF oracle exercised** — the canary received **zero** inbound hits
  across all sinks (and you confirm the canary was actually reachable — see below).

State the verdict **per sink class** (metadata / loopback / RFC-1918 / canary /
internal-leak / mgmt-routes), not as one blanket word.

---

## Blocked conditions

Flag loudly; never let a block masquerade as `clean`.

- **Sink is auth-gated and no/insufficient cred** → `blocked: needs cred`.
  *Unblocks:* manager supplies a session/account in the brief; pass it via
  `security_scan.session` / `testAccounts[]` and re-run (B)–(C).
- **No canary host available** → say so explicitly. This means **blind SSRF is
  unconfirmable**: sinks that fetch but return nothing inline can't be proven or
  cleared. Downgrade those to `blocked: needs OOB canary`, not `clean`.
  *Unblocks:* manager provisions an Interactsh-style OOB domain/IP.
- **Active probes / templates disabled by policy** (`includeActiveProbes` or
  `includeTemplates` off, or `bruteForce` unauthorized) → `blocked: needs active
  probing authorized`. *Unblocks:* operator re-runs with those flags on.
- **No SSRF sinks found at all** → that is a *finding-absent* PASS for (B)/(C)
  only if (A) was thorough; still run (D). Don't infer clean for leakage/mgmt from
  "no sinks".

---

## Return contract

Return exactly this object to the manager:

```json
{
  "class": "ssrf-internal",
  "verdict": "vulnerable | clean | blocked",
  "blockedReason": "needs cred | needs OOB canary | needs active probing authorized | null",
  "endpointsTested": 0,
  "endpointsTotal": 0,
  "findings": [
    {
      "title": "",
      "severity": "critical | high | medium | low | info",
      "confidence": "confirmed | firm | tentative",
      "category": "ssrf-internal",
      "description": "",
      "evidence": "canary fetch/DNS hit, metadata 200 body, leaked host/IP, actuator response — verbatim, minimal",
      "impact": "",
      "remediation": "",
      "attackChain": "sink → payload/bypass → internal target reached (canary/metadata proof)"
    }
  ],
  "notes": "per-sink-class verdicts; bypasses tried; canary reachability; anything left blocked + its unblock"
}
```

- `endpointsTested` / `endpointsTotal` = sinks you drove vs. sinks enumerated in
  (A); if tested < total, the gap goes in `notes` with the reason.
- `verdict: clean` requires every proof in **Proof required to claim clean**.
  Otherwise `vulnerable` (with findings) or `blocked` (with `blockedReason`).
- Keep `evidence` minimal per prove-don't-pillage — one canary line, one metadata
  token, one leaked host. Do not dump harvested credentials.
