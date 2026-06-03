# Design: "No-Stone-Unturned" upgrade to security-mcp

Date: 2026-06-03
Status: Approved (build all 5 parts; safe probes + self-registration)

## Problem

The autonomous `/audit` skill misses vulnerabilities because the **discovery**
stage is link-only. `crawler.ts` follows `<a href>`, `<form>`, and inline
`fetch/axios` calls, plus a tiny curated well-known list. It never brute-forces
paths, reads `robots.txt`/`sitemap.xml`, mines JS bundles, or discovers hidden
parameters. Worse, `attack-surface.ts` only marks injection/API goals
"applicable" when an endpoint has a query string or a form — so JSON/REST APIs
get their injection checks silently skipped. Detection depth (probes, prompts,
templates) also has gaps (no SSTI/XXE/GraphQL/JWT-alg/host-header/NoSQL/CORS).

You cannot test an attack surface you never found. This upgrade widens
discovery first, then deepens detection — all inside the existing rules of
engagement (safe GETs, budget-capped, non-destructive).

## Goals

1. Find dramatically more attack surface (discovery breadth).
2. Auto-establish identities (self-register multiple throwaway accounts, with
   self-healing retries) so authenticated/access-control checks actually run.
3. Deepen the active-probe library.
4. Add missing vuln-class reasoning prompts.
5. Add more nuclei-style YAML templates.

All new capability wires into `security_scan` so the `/audit` skill benefits
with zero workflow change.

## Architecture

### 1. Discovery breadth (`src/core/scanner/`)
- **`recon.ts`** — fetch+parse `robots.txt` (Disallow/Allow/Sitemap) and
  `sitemap.xml` (`<loc>`), turning each path into a `DiscoveredEndpoint`
  (`source: 'recon'`). Read-only, budget-bounded.
- **`content-discovery.ts`** — wordlist brute-force of high-signal paths/files.
  New `wordlists/common-paths.txt`. Each candidate is a safe GET; only
  non-404/!error responses are recorded (`source: 'content-discovery'`).
  Capped by `SCAN_MAX_REQUESTS` and a new `SCAN_WORDLIST_MAX` env cap; gated by
  `SCAN_CONTENT_DISCOVERY` (default on for deep scans).
- **`js-endpoint-extractor.ts`** — download same-origin `.js` assets referenced
  by crawled pages and regex out API path strings / `fetch`/`axios`/route
  literals (`source: 'js-bundle'`).
- **Fix `attack-surface.ts`** — also treat `/api/*` paths, JSON content-type
  endpoints, and non-GET methods (POST/PUT/PATCH/DELETE) as input-bearing so
  injection/API goals are not skipped on bodied REST/JSON APIs.

### 2. Self-registration + self-healing (`src/core/scanner/auto-register.ts`)
- Discover the signup surface (form named register/signup, or a known
  `POST /register|/signup|/api/auth/register`, or one from a parsed API spec).
- Register **N>=2 throwaway accounts** through the public flow (own accounts
  only). Capture session (cookies / bearer token).
- Attempt privilege escalation at the registration boundary
  (mass-assignment): submit `role=admin`, `is_admin=true`, `isAdmin`,
  `permissions:["*"]`, `accountType=admin`, `groups:["administrators"]`, then
  read back `/me`/`/account`/JWT claims to see whether the server honored them
  (critical finding if so).
- **Self-healing:** on failure (non-2xx, validation error, captcha), retry with
  backoff and alternate field-name guesses (email/username/user, password/pass,
  password_confirmation, name); cap total attempts; never touch existing
  accounts; surface a clear note if signup is closed.
- Output: an `AutoRegisterResult` carrying synthesized `TestAccount` entries +
  findings, fed back so multi-role differential / IDOR / BOLA can run.
- Gated by a `registerAccounts` request flag (default off; the `/audit` skill
  turns it on). Strictly localhost/allowlisted, validated per request.

### 3. Deeper probes (`src/core/scanner/probe-library.ts`)
Add safe, signal-only probes + extend the category union:
`ssti`, `xxe`, `graphql-introspection`, `jwt-alg`, `host-header-injection`,
`nosql-operator`, `cors-misconfig`, `clickjacking`.

### 4. New prompt modules (`src/core/prompt-engine/prompts/`)
Add + register: `injection.ssti`, `injection.xxe`,
`api.graphql`, `headers.clickjacking`, `configuration.secret-scanning`,
`api.web-cache-deception`.

### 5. New YAML templates (`templates/`)
`.git/HEAD`, `.git/config`, `docker-compose.yml`, `.DS_Store`, `id_rsa`,
`phpmyadmin`, `.npmrc`/`.netrc`, CI config files, `/server-info`, etc.

## Safety
- Every new HTTP path goes through `validateTarget` and shares the crawl
  request budget. No destructive/state-changing payloads (except own-account
  self-registration, explicitly authorized). Max-variant caps preserved.

## Testing
- One vitest file per new module under `src/tests/`, matching existing style.
- `npm run typecheck` + `npm test` green before running the live audit.

## Out of scope
- Subdomain/vhost discovery (irrelevant for localhost).
- Standalone CLI entrypoints (chose engine-integration only).
