# Critical coverage — the classes that MUST be proven before an audit is "done"

These are the high-impact breach classes. For each, the audit must reach a
**definitive, evidence-backed verdict** — `vulnerable`, `clean`, or
`blocked: <reason>` — and may **never** leave one silently untested or call it
`clean` without the proof described here. If a class can't be conclusively
tested in scope (e.g. needs a credential you don't have), say so **loudly** at
the top of the report — an honest "UNVERIFIED — needs X" is the goal, never a
false "clean".

> Honesty rule: there is no "100% no bugs" claim. The guarantee this checklist
> enforces is *no class is silently skipped* — every one is either proven or
> flagged with exactly what's blocking it and how to unblock it.

## 1. IDOR / BOLA (object-level authorization) — OWASP API1
- **Test:** with two accounts, request account A's object ids (`/{id}`, UUIDs,
  numeric ±1) while authenticated as account B; diff the body to confirm it's
  A's data. Cover GET and (own-object only) PATCH/DELETE reasoning.
- **Proof to claim clean:** A's ids return 401/403/404 to B across a sample of
  id-shaped routes, with the multi-role differential actually run.
- **Blocked when:** fewer than two verified accounts → `blocked: needs 2 creds`.

## 2. Privilege escalation (vertical) — OWASP API3/API5
- **Test:** (a) mass-assignment at **registration** (`role=admin`…); (b) **profile
  update** role change (`PATCH /me|/profile|/account` with role/isAdmin/domain
  role — student→teacher, member→owner — the `profile-escalation` prober); (c)
  BFLA on admin functions (unauth + low-priv + method/header/path tricks).
- **Proof to claim clean:** injected privilege fields are rejected/ignored on
  read-back AND admin functions deny non-admins.
- **Blocked when:** no authenticated identity → acquire one (Step 1.5–1.7) or
  `blocked: needs cred`.

## 3. Cloud storage exposure (S3 / GCS / Azure Blob) — data leak
- **Test:** `cloud-storage-exposure` module — bucket/object URLs and
  presigned/SAS URLs in responses, spec, JS, redirect headers; assess
  public-list / public-read (in scope only; report bucket names for
  out-of-scope manual `aws s3 ls --no-sign-request`).
- **Proof to claim clean:** no bucket/object/presigned references in any
  client-reachable content.

## 4. VPC / internal-network exposure (SSRF + internal services)
- **Test:** SSRF sinks (URL/webhook/import/fetch params, link/report-share) —
  point them at `http://169.254.169.254/...` (cloud metadata), `http://localhost`,
  RFC-1918 ranges, and a canary host; watch for fetch/DNS evidence. Also: internal
  hostnames/IPs/private endpoints leaking in responses or the spec, and exposed
  management/`/internal`/`/actuator` routes.
- **Proof to claim clean:** SSRF sinks reject internal targets; no internal
  hosts/IPs leak; metadata endpoint unreachable via the app.
- **Blocked when:** sinks are auth-gated → `blocked: needs cred`.

## 5. Database exposure
- **Test:** exposed DB admin UIs / ports (mongo-express, Elasticsearch, Kibana,
  Adminer, phpMyAdmin — templates), DB **connection strings / credentials** in
  client-reachable content (secret-scanning), and SQL/NoSQL **injection** on every
  reachable input using the inferred payloads.
- **Proof to claim clean:** no exposed DB console/port reachable, no DB creds
  leak, injection markers don't trigger DB errors/latency on tested inputs.
- **Note:** raw port scanning may be out of policy — say so rather than skip silently.

## 6. Authn / authz on EVERY route (auth vs unauth)
- **Test:** hit every discovered route (documented + `api-discovery`)
  unauthenticated; then as a low-priv account. A 2xx where auth/role should be
  required is the break. Also: JWT hygiene (alg:none, forged), verification-gate
  bypass, session/cookie flags.
- **Proof to claim clean:** protected routes return 401/403 unauth and enforce
  role for low-priv principals, across the FULL route inventory (not a sample).

---

### The completion gate
The audit is **not done** until every class above is `vulnerable` / `clean` /
`blocked:<reason>` with the stated proof. The report must open with a
**coverage attestation**: per class, the verdict and (if blocked) the one thing
needed to finish it. Treat a `blocked` as an action item for the operator, not a
pass.
