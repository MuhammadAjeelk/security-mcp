# Playbook 03 — Injection (SQLi · NoSQLi · command · XSS · SSTI · XXE · path-traversal · deserialization)

**Mission:** you are SPECIALIST #3. Take every reachable input in the SHARED BRIEF and prove
whether attacker-controlled data crosses into an interpreter — a SQL engine, a NoSQL query, a
shell, an HTML/JS context, a template engine, an XML parser, a filesystem path, or an object
deserializer. Reach a definitive, evidence-backed verdict per injection type: `vulnerable`,
`clean`, or `blocked: <reason>`. **prove-don't-pillage** — detection/marker payloads ONLY
(boolean/time-based, canary tokens, harmless reflection markers). NEVER destructive ones: no
`DROP`, no `rm`, no `DELETE`, no data mutation. Use your own-account inputs. Honesty rule per
[critical-coverage.md](../critical-coverage.md): no `clean` without the stated proof, no silent
skips, every blocked sub-test flagged with the one thing that unblocks it.

## Inputs from the SHARED BRIEF
- **Route inventory** — every reachable input: query params, path params, JSON body fields,
  headers, cookies, multipart fields. This is your injection-point universe.
- **`evidence.apiPayloadHints`** — inferred request bodies/shapes for bodied endpoints (from
  `api-payload-finder.ts`). These are the valid JSON shapes you mutate; without them you'd send
  malformed bodies that 400 before reaching the interpreter.
- **Credential(s)** — the acquired identity. Authed inputs are reachable only with this; if a
  sink is auth-gated and you have no cred, it's `blocked: needs cred`, not `clean`.

## Weapons
- `injection.sql` — prompt-loop goal: boolean/time-based/error-based SQLi across reachable inputs.
- `injection.nosql` — operator-injection (`$ne`/`$gt`) against Mongo-style query params/bodies.
- `injection.command` — OS command injection via shell-metacharacter time delays.
- `injection.xss` — reflected/stored/DOM cross-site scripting via canary markers.
- `injection.ssti` — server-side template injection via arithmetic polyglots.
- `injection.xxe` — XML external entity against XML-accepting endpoints.
- `injection.path-traversal` — `../` traversal to filesystem markers; ties to `files.insecure-access`.
- `api.deserialization` — unsafe object deserialization via risky content-types/object payloads.
- **`api-payload-finder.ts` / `evidence.apiPayloadHints`** — supplies the body shapes; inject your
  markers into EVERY field of EVERY reachable bodied endpoint, not just the obvious ones.
- **`security_scan`** — drive with `targetUrl`, `scanType`, `includeActiveProbes: true`,
  `includeTemplates: true` (DB-console templates corroborate SQLi surface),
  `includeContentDiscovery: true`, `session`/`testAccounts[]` to carry the cred into authed sinks.
- **`run_prompt_loop`** — run the goal ids above against collected evidence; one input at a time.
- **`browser`/`WebFetch`** — confirm XSS *execution* (not just reflection) and DOM sinks in a real page.

## Method — inject every reachable input
1. **Enumerate injection points.** Walk the route inventory and `apiPayloadHints`. For each
   endpoint emit one point per: query param, path segment, JSON body field (recurse nested
   objects/arrays), custom header, cookie value, multipart field name + value. Record
   method + content-type — it decides which interpreter is downstream.
2. **Baseline every point.** Send a benign valid value (own-account data, from the payload hint
   shape). Capture status, body length, response time, error fingerprints. Every detection below
   is a *differential* against this baseline — no baseline, no signal.
3. **Type-route each point.** JSON body field → SQLi + NoSQLi + SSTI + command + deserialization.
   String/path param → SQLi + path-traversal + SSTI + command. Reflected-in-response value → XSS.
   `Content-Type: application/xml` or a field that looks like XML → XXE. Header/cookie → SQLi +
   command + reflection (log/HTML).
4. **One marker at a time.** Never combine payloads — you must attribute the signal. Run each
   `injection.*` goal point-by-point; keep raw request/response pairs as evidence.

## Ordered checklist
Run all eight. Mark each `vulnerable` / `clean` / `blocked:<reason>`.

### 1. SQL injection — `injection.sql`
- **Where:** any param/body field/header reaching a relational query (search, filter, sort,
  `id`, login).
- **Boolean-based (non-destructive):** send the TRUE form `' OR '1'='1` and the FALSE form
  `' AND '1'='2` for the same point; diff bodies. **Vulnerable** = the two responses differ in
  row count / length / status in a way that tracks the truth value.
- **Time-based (non-destructive):** inject a provider-correct sleep marker (e.g.
  `'; SELECT pg_sleep(5)-- -`, `' OR SLEEP(5)-- -`, `'||dbms_pipe.receive_message(...,5)`).
  **Vulnerable** = response latency jumps ~5s vs sub-second baseline, repeatably.
- **Error-based:** a single quote / unbalanced syntax returns a DB error string
  (`SQLSTATE`, `ORA-`, `syntax error at or near`, `MySqlException`). **Vulnerable** = DB error leaks.
- **Pass/fail:** vulnerable if ANY of differential / latency / error fires; clean only if none fire
  across all SQL-routed points.

### 2. NoSQL injection — `injection.nosql`
- **Where:** Mongo/Elastic-style query params and JSON body fields, especially auth and filter
  endpoints.
- **Technique:** swap a string field for an operator object — `{"$ne":null}`, `{"$gt":""}`,
  `{"$regex":".*"}` — using the `apiPayloadHints` shape. Also try the string form
  `field[$ne]=` for query-string params. **Vulnerable** = the operator form returns MORE rows /
  bypasses a filter / authenticates where the literal value would not (differential vs baseline).
- **Pass/fail:** clean only if operator objects are rejected or behave identically to a literal
  string across all NoSQL-routed points.

### 3. Command injection — `injection.command`
- **Where:** fields that feed a shell — filename/path, host/ping, format/convert, export, archive.
- **Technique (TIME-BASED ONLY, non-destructive):** append shell-metachar delays —
  `; sleep 5`, `| sleep 5`, `$(sleep 5)`, `` `sleep 5` ``, `& ping -c 5 127.0.0.1`. NEVER `rm`,
  `cat /etc/shadow`, or any mutating/exfil command. **Vulnerable** = injected delay reproducibly
  adds ~5s latency vs baseline.
- **Pass/fail:** clean only if no metachar variant produces a delay differential on any
  shell-routed point.

### 4. XSS — `injection.xss`
- **Where:** any value reflected into an HTML/JS/attribute response, or written then rendered
  (stored), or read by client JS into a sink (DOM).
- **Reflected:** send a unique canary (`zz<x9k1>'"`) into each point; fetch the response and
  check whether the canary is reflected **unescaped** (raw `<`/`>`/`"` in HTML context).
  **Vulnerable** = canary lands in an executable context unescaped.
- **Stored:** write the canary via your own account; reload the rendering view; check for the
  same unescaped reflection.
- **DOM:** use `browser`/`WebFetch` to load the page with the canary and confirm the marker
  reaches a sink. **Confirm execution** with the browser tools (e.g. a benign
  `<img src=x onerror=...marker...>` firing) — reflection alone is suspicious, execution is proof.
- **Pass/fail:** clean only if every canary is HTML-encoded / not reflected and no DOM sink executes.

### 5. SSTI — `injection.ssti`
- **Where:** params/body fields rendered through a server template (names, subjects, templated
  emails, report titles).
- **Technique:** send the arithmetic polyglot `${7*7}{{7*7}}#{7*7}<%= 7*7 %>` into each point.
  **Vulnerable** = the response contains `49` (the engine evaluated the expression). Confirm the
  engine with a second harmless eval (`{{7*'7'}}` → `7777777` for Jinja).
- **Pass/fail:** clean only if no point ever returns `49`/evaluated output; literal echo of the
  payload = clean for that point.

### 6. XXE — `injection.xxe`
- **Where:** endpoints accepting `application/xml`/`text/xml` or XML-shaped fields (SOAP, SVG
  upload, sitemap/import).
- **Technique (non-destructive, ties to SSRF canary):** post XML declaring an external entity
  pointing at the **SHARED BRIEF canary host** (out-of-band) and a benign local file entity:
  `<!DOCTYPE r [<!ENTITY x SYSTEM "http://CANARY-HOST/xxe-03">]><r>&x;</r>`. Do not exfil real
  secrets — the canary fetch is the proof. **Vulnerable** = the parser fetches the canary host
  (DNS/HTTP hit) OR reflects the file entity's content.
- **Pass/fail:** clean only if external entities are not resolved (no canary fetch, no entity
  expansion) on any XML-accepting endpoint.

### 7. Path traversal — `injection.path-traversal` / `files.insecure-access`
- **Where:** filename/path/download/template/include params and multipart filenames.
- **Technique:** request a non-sensitive marker via traversal — `../../../../etc/passwd`,
  encoded `..%2f..%2f`, double-encoded `..%252f`, and null-byte `....//`/`%00` variants — reading
  only well-known read-only markers (e.g. `/etc/passwd`, `/etc/hostname`). **Vulnerable** = the
  response returns out-of-tree file content (e.g. `root:x:0:0:` lines) or differs from the
  in-bounds baseline in a way that proves directory escape. Cross-reference the
  `files.insecure-access` surface for unguarded static/download routes.
- **Pass/fail:** clean only if every traversal variant is normalized/rejected and no out-of-tree
  content is returned.

### 8. Deserialization — `api.deserialization`
- **Where:** endpoints accepting serialized objects — `Content-Type:
  application/x-java-serialized-object`, PHP-serialized strings, Python pickle, .NET
  `__type`/`$type` JSON, YAML with tags, base64 object blobs in cookies/params.
- **Technique (non-destructive):** flag risky content-types/shapes; send a **benign type-probe**
  (e.g. a malformed-but-typed object, or a canary-tagged YAML `!!str`) and observe parser behavior.
  Do NOT send gadget chains or RCE payloads — detect the unsafe surface, then escalate manually
  only with operator sign-off. **Vulnerable signal** = the endpoint deserializes attacker-typed
  objects (type confusion, parser stack traces revealing native deser, distinct handling of the
  typed probe).
- **Pass/fail:** clean only if no endpoint accepts/native-deserializes attacker-controlled object
  formats; flag any risky content-type as `vulnerable`/needs-manual-confirm with evidence.

## Proof required to claim clean
Per type, `clean` is allowed ONLY with this captured:
- **SQLi:** boolean differential is null AND no sleep-marker latency AND no DB error string across
  all SQL-routed points (cite the points + raw timings/responses).
- **NoSQLi:** operator objects rejected or behave identically to a literal across all points.
- **Command:** no metachar variant adds latency on any shell-routed point (cite baseline vs payload ms).
- **XSS:** canary is HTML-encoded / not reflected AND no DOM sink executes (browser-confirmed).
- **SSTI:** no point returns `49`/evaluated output — only literal echo.
- **XXE:** no canary fetch and no entity expansion on any XML endpoint.
- **Path traversal:** every variant normalized/rejected, no out-of-tree content returned.
- **Deserialization:** no endpoint native-deserializes attacker-typed object formats.

## Blocked conditions
- **Auth-gated input, no cred** → for that point: `blocked: needs cred`. Unblock: acquire the
  credential (manager Step 1.5–1.7) or pass `session`/`testAccounts[]` into `security_scan`.
- **WAF blocking** → if payloads are uniformly 403/406/429-dropped (not app behavior), record
  `blocked: WAF` with the trigger and tested points. Unblock: confirm with the operator whether
  WAF is in-scope; try light non-destructive encoding/casing variation to distinguish WAF from a
  real fix — but DO NOT pivot to evasion/destructive payloads.
- **No `apiPayloadHints` for a bodied endpoint** → body fields are unreachable without a valid
  shape: `blocked: needs payload shape`. Unblock: re-run `api-payload-finder` / capture a real
  request. Never report such an endpoint `clean`.
- **No XML/serialized endpoints in inventory** → XXE/deser are `clean (no applicable surface)` —
  state that explicitly, don't silently drop them.

## Return contract
Return exactly this object to the manager:

```json
{
  "class": "injection",
  "verdict": "vulnerable | clean | blocked",
  "blockedReason": "<null, or e.g. 'needs cred for authed sinks' | 'WAF' | 'needs payload shape'>",
  "endpointsTested": 0,
  "endpointsTotal": 0,
  "findings": [
    {
      "title": "",
      "severity": "critical | high | medium | low | info",
      "confidence": "firm | tentative",
      "category": "sqli | nosqli | command | xss | ssti | xxe | path-traversal | deserialization",
      "description": "",
      "evidence": "raw request/response pair, latency deltas, reflected canary, or DB error string",
      "impact": "",
      "remediation": "",
      "attackChain": "how this injection chains into RCE / data theft / auth bypass"
    }
  ],
  "notes": "per-type verdict table; blocked points with the one unblock each; WAF/encoding observations"
}
```

Set `verdict: vulnerable` if ANY type fires; `blocked` if a critical sub-test couldn't run; else
`clean` — and only with every proof above captured. `endpointsTested` vs `endpointsTotal` must
expose any gap; if they differ, the delta belongs in `notes` with its blocked reason.
