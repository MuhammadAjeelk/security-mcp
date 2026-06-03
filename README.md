# security-mcp

Internal MCP server for **authorized** security testing against **localhost or allowlisted staging** targets. Wires to Claude Code, Cursor, or any other MCP-compatible client. Generates Markdown + JSON reports.

> This tool is for security testing of systems you own or are explicitly authorized to test.
> The target policy hard-rejects anything that smells like production. Do not patch it out.

## What it does

- **Crawls** an allowlisted target with `undici`, capturing headers, cookies, forms, and endpoints.
- **API surface enumeration** — on `standard`/`deep` scans, auto-probes well-known doc/spec paths (`/api/docs`, `/swagger`, `/openapi.json`, `/v3/api-docs`, `/graphql`, …) and parses any Swagger/OpenAPI spec it finds into the endpoint inventory (sources `well-known` / `api-spec`), surfacing operations the HTML crawl never links.
- **Multi-role differential probe** — re-hits discovered endpoints with each supplied `testAccounts` role to surface IDOR / BOLA / privilege escalation / tenant isolation.
- **Active safe-payload library** (`includeActiveProbes: true`) — non-destructive markers for SQLi, XSS, CRLF, SSRF, path traversal, command injection. Confirms vulns without exploitation.
- **Nuclei-style YAML template engine** (`includeTemplates: true`) — 30 bundled templates covering exposed env/git/swagger/lockfiles, Spring Actuator, Django/Flask/Laravel debug pages, phpinfo, missing security headers, dangerous CORS configs, exposed Jenkins/Grafana/Kibana/Elasticsearch/mongo-express. User-extensible via `templates/*.yaml`.
- **Prompt registry** of 39 security modules across access-control, authentication, injection, api-security, business-logic, files, configuration, infrastructure, multi-tenant. Deterministic heuristic + long-form LLM prompt per module.
- **Pluggable LLM client**: `MockLLMClient` (default) or `AnthropicLLMClient` (set `LLM_PROVIDER=anthropic` + `ANTHROPIC_API_KEY`). System prompt is cached so iterative loops are cheap.
- **Auth session passthrough**: pre-captured `{ cookies, bearerToken }` threaded through crawler + probes + templates.
- **Ralph Loop autonomous mode** (`/security-mcp:ralph <url>`) — drives security-mcp through iterative scans until coverage is satisfied.
- **Severity AND confidence on every finding** — the system never claims 100% certainty.
- Writes Markdown + JSON reports to `REPORTS_DIR`.

## Install

```bash
npm install
cp .env.example .env
# edit .env to list any staging hostnames
```

Optional extras (only install if you need them):

```bash
npm i playwright            # for includeBrowserTests:true
npx playwright install chromium
npm i bullmq ioredis        # only if you implement the bullmq job runner
```

## Run

```bash
npm run dev        # tsx watch (stdio)
npm run build      # compile to dist/
npm start          # node dist/server.js (stdio)
npm test           # vitest
npm run typecheck  # tsc --noEmit
```

## MCP tools exposed

| Tool | Purpose |
|---|---|
| `validate_target` | Check whether a URL is allowed under the policy. Always call first. |
| `security_scan` | Full crawl + multi-role probe + prompt loop + report. |
| `run_prompt_loop` | Run prompts against pre-supplied evidence (single-pass or iterative). |
| `generate_report` | Produce Markdown + JSON from findings + evidence. |

### `security_scan` input

```json
{
  "targetUrl": "http://localhost:3000",
  "scanType": "standard",
  "maxDepth": 2,
  "includeBrowserTests": false,
  "allowedHosts": ["qa.example.com"],
  "testAccounts": [
    { "role": "user-a", "token": "..." },
    { "role": "user-b", "cookies": { "session": "..." } }
  ]
}
```

- `testAccounts` is optional. Pass **two or more** to unlock BOLA / privilege-escalation / tenant-isolation differential checks.
- `tokens` and `cookies` are used to authenticate probe requests but are **never written into reports**.

## Environment

| Var | Default | Description |
|---|---|---|
| `MCP_MODE` | `stdio` | `stdio` (V1) or `http` (scaffold only) |
| `MCP_API_KEY` | _empty_ | Reserved for future HTTP transport |
| `ALLOWED_STAGING_HOSTS` | _empty_ | Comma-separated allowlist of staging hostnames |
| `SCAN_TIMEOUT_MS` | `10000` | Per-request timeout |
| `SCAN_MAX_REQUESTS` | `50` | Total requests per scan |
| `SCAN_MAX_DEPTH` | `2` | Crawl depth ceiling |
| `PROMPT_LOOP_MAX_ITERATIONS` | `3` | Iterative loop cap |
| `REPORTS_DIR` | `./reports` | Output directory |
| `LLM_PROVIDER` | `mock` | Pluggable. `mock` only in V1. |

## Target policy

**Allowed**

- `localhost`, `127.0.0.1`, `::1`
- Hostnames in `ALLOWED_STAGING_HOSTS`
- Per-call `allowedHosts` override

**Blocked**

- Any hostname containing `production`, `prod`, or `live`
- Cloud metadata IPs (`169.254.169.254`)
- Private network ranges (10/8, 172.16/12, 192.168/16, 169.254/16) unless allowlisted
- Non-http/https schemes
- Redirects that resolve to a non-allowed host
- Unknown public hostnames

## Install as a Claude Code plugin (recommended)

This repo ships as a Claude Code plugin: it registers the MCP server **and** adds slash commands automatically. The compiled server (`dist/server.js`) is committed and self-contained, so **no build step is required** — just two commands in Claude Code:

```
/plugin marketplace add MuhammadAjeelk/security-mcp
/plugin install security-mcp@security-mcp
```

> `/plugin marketplace add` registers this GitHub repo as a marketplace on your machine (a one-time step). `/plugin install` then pulls the plugin from it. After that, anyone can update with `/plugin marketplace update security-mcp`.

**Local development install** (working inside a clone of this repo instead):

```
/plugin marketplace add ./
/plugin install security-mcp@security-mcp
```

Restart Claude Code. You now have:

- `/security-mcp:scan <url> [quick|standard|deep]`
- `/security-mcp:validate <url>`
- `/security-mcp:loop <url> [single-pass|iterative]`
- `/security-mcp:report <url>`
- `/security-mcp:help`

…and the four MCP tools (`validate_target`, `security_scan`, `run_prompt_loop`, `generate_report`) registered automatically.

### Configuring the plugin

Edit `.claude-plugin/plugin.json` to set `ALLOWED_STAGING_HOSTS` (or override at the OS env level). The plugin reads env vars at MCP startup, so changes require a Claude Code restart.

## Alternative: manual MCP config (without the plugin)

```jsonc
// ~/.claude/mcp.json  (or per-project .claude/mcp.json)
{
  "mcpServers": {
    "security-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/security-mcp/dist/server.js"],
      "env": {
        "ALLOWED_STAGING_HOSTS": "staging.example.com,dev.example.com",
        "SCAN_TIMEOUT_MS": "10000",
        "SCAN_MAX_REQUESTS": "50",
        "PROMPT_LOOP_MAX_ITERATIONS": "3",
        "REPORTS_DIR": "/absolute/path/to/security-mcp/reports"
      }
    }
  }
}
```

## Cursor MCP config

```jsonc
// ~/.cursor/mcp.json
{
  "mcpServers": {
    "security-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/security-mcp/dist/server.js"],
      "env": {
        "ALLOWED_STAGING_HOSTS": "staging.example.com"
      }
    }
  }
}
```

## Local testing recipe

1. Start any localhost app (e.g. `npm run dev` on a sample project at `http://localhost:3000`).
2. In Claude Code / Cursor, call `validate_target` with that URL — confirm allowed.
3. Call `security_scan` with `scanType: "standard"`.
4. Open the markdown report from `./reports/`.

## Adding a new prompt

1. Create `src/core/prompt-engine/prompts/<category>/<name>.prompt.ts`.
2. Export a `SecurityPrompt` with `id`, `title`, `category`, `severityFocus`, `prompt`, and an optional `heuristic(ctx)` that produces `PromptFinding[]`.
3. Register it in `src/core/prompt-engine/prompt-registry.ts`.
4. Add a Vitest case if the heuristic is non-trivial.

Prompts MUST:

- only act within allowed targets
- be non-destructive (no mutating verbs against foreign tenants)
- always emit both `severity` and `confidence`
- include `impact` and `remediation`

## Adding a new staging host

Either:

- Add it to `ALLOWED_STAGING_HOSTS` in `.env` (preferred — survives restarts), OR
- Pass it in `allowedHosts` on the tool call (per-call override).

## Localhost limitation (important)

If you ever **host** this MCP server (HTTP transport), it will run in a network namespace that **cannot reach a developer's localhost**. For localhost testing you have three options:

1. **Run security-mcp locally** alongside the app (default V1 mode — recommended).
2. **Use a secure tunnel** (e.g. `cloudflared`, `tailscale serve`, `ngrok`) to expose the local app to the hosted MCP. Tunnel domains must be added to `ALLOWED_STAGING_HOSTS`.
3. **Run a lightweight local agent** that the hosted MCP can dispatch scan requests to (future work, not in V1).

## Roadmap (not in V1)

- Real LLM clients (Anthropic / OpenAI / Bedrock) plugged into `LLMClient`.
- Streamable HTTP transport with `MCP_API_KEY` auth.
- BullMQ job runner for long scans (interface already present).
- Headless-browser deep checks (DOM XSS, CSP enforcement live).
