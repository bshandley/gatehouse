# AGENTS.md

## Overview

`gatehouse` is a self-hosted secrets vault for AI agents. It exposes a REST API under `/v1` and an MCP server at `/v1/mcp` (plus a stdio MCP entry point, `src/mcp-stdio.ts`). Agents authenticate with AppRole credentials and receive a JWT. Depending on their policies they can read, list, write, delete, lease, or proxy secrets.

## Quick Start for Agents

1. **Onboard**: fetch the onboarding markdown provided by the operator:
   ```bash
   curl -fsSL "https://gatehouse.example/v1/onboard/<token>" > /tmp/onboard.md && cat /tmp/onboard.md
   ```
   Follow the instructions to exchange the bootstrap token (`POST /v1/onboard/<token>/exchange`, single use) for `role_id`, `secret_id` and a JWT.
2. **Store credentials**: set environment variables for the runtime:
   ```bash
   export GATEHOUSE_ROLE_ID=...
   export GATEHOUSE_SECRET_ID=...
   export GATEHOUSE_TOKEN=...
   ```
3. **Refresh token** (optional, for long-running agents):
   ```bash
   curl -X POST http://localhost:3100/v1/auth/refresh \
     -H "Authorization: Bearer $GATEHOUSE_TOKEN"
   ```
   Replace `$GATEHOUSE_TOKEN` with the new token from the response.

## Core API Endpoints

All endpoints except login and onboarding need `Authorization: Bearer <JWT>`.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/auth/approle/login` | POST | Exchange `role_id`/`secret_id` for a JWT. |
| `/v1/auth/refresh` | POST | Refresh a still-valid JWT (24 h TTL). |
| `/v1/auth/whoami` | GET | Inspect the current token (identity, policies, expiry). |
| `/v1/secrets` | GET | List secret paths you can access (`?prefix=` optional). |
| `/v1/secrets/:path` | GET | Read a secret's metadata (requires any of `read`, `list`, `proxy`, `lease`). |
| `/v1/secrets/:path/value` | GET | Read a secret's value (requires `read`). |
| `/v1/secrets/:path` | POST | Create or update a secret (requires `write`). |
| `/v1/secrets/:path` | PATCH | Update a secret's metadata only (requires `write`). |
| `/v1/secrets/:path` | DELETE | Delete a secret (requires `delete`). |
| `/v1/lease/:path` | POST | Check out a time-limited lease on a static secret (requires `lease`). Body: `{"ttl": seconds}`, 10 to 86400, default 300. |
| `/v1/dynamic/:path/checkout` | POST | Check out temporary credentials from a dynamic secret (requires `lease`). |
| `/v1/proxy` | POST | Make an HTTP call through Gatehouse without seeing the raw secret (requires `proxy` on each secret used). |
| `/v1/proxy/patterns?secret=<path>` | GET | Verified request shapes for a secret (requires `proxy` or `read`). |
| `/v1/skill` | GET | Fetch the skill markdown tailored to the agent's policies. |

### Proxy request shape

`POST /v1/proxy` takes the target request as a JSON body. The path is always `/v1/proxy`; the secret is named in the body, not in the URL.

```bash
curl -X POST http://localhost:3100/v1/proxy \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "https://api.example.com/v1/things",
    "auto_inject": ["api-keys/example"]
  }'
```

Three ways to reference a secret, which can be combined:

- `auto_inject: ["<path>"]`: Gatehouse sets the header named by the secret's `metadata.header_name`.
- `inject: {"Header-Name": "<path>"}`: sets that header to the secret value.
- `{{secret:<path>}}` placeholders in `url`, `headers`, or `body`.

The response is `{"status": ..., "headers": {...}, "body": ...}` with the upstream status, headers and body.

## Policy-Based Capabilities

Agents are assigned one or more policies (see `config/policies/*.yaml`). The capabilities are:

- `read`: fetch secret values.
- `list`: enumerate secret paths under a prefix.
- `write`: create or update secrets.
- `delete`: remove secrets.
- `lease`: obtain time-limited leases and dynamic credentials.
- `proxy`: make HTTP calls using the secret without ever seeing the raw value.
- `admin`: full management rights (rare for agents).

If an API call returns `403` with `{"error":"Forbidden","request_id":"..."}` the agent's policy does not grant the needed capability.

## Secret Discovery Patterns

When listing secrets, each static secret in the response includes:

- `caps`: the capabilities you hold on that path.
- `pattern_count`: how many verified request shapes exist for this secret.
- `top_pattern`: a representative `METHOD url_template` that works out of the box (present when `pattern_count > 0`).

If `pattern_count > 0` retrieve the full patterns via:
```bash
curl "http://localhost:3100/v1/proxy/patterns?secret=<path>" \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN"
```
Use the returned method, URL, headers and body schema to call the secret without trial and error.

If `pattern_count == 0` fall back to `metadata.allowed_domains` to discover the host you may contact. The first successful proxy call seeds a pattern for downstream agents.

## Development Workflow (for contributors)

- **Run**: `bun run dev` starts the server and restarts it when TypeScript sources change.
- **Test**: `bun test` runs the full suite under `test/` (Bun's built-in test runner).
- **Database schema**: there is no migration command. `src/db/init.ts` creates and upgrades the SQLite schema at startup.
- **Site docs**: `cd site && bun run dev` runs the Astro dev server for the documentation site.

## Gotchas & Tips

- The JWT expires after 24 h. Handle `401` by refreshing or logging in again.
- `secret_id` is a credential, **not** a secret path. Keep it: it is needed to log in again once the JWT has expired and can no longer be refreshed.
- Proxy mode never returns the secret value. Gatehouse buffers the upstream response and redacts any echoed secret values before returning it.
- Policies are defined in `config/policies/*.yaml` or managed through the `/v1/policy` API. After editing the YAML files, an admin applies them with `POST /v1/policy/reload`; no restart is needed.
- API paths are relative to the server's base URL (`http://<host>:3100` by default). The port is set on the server with `GATEHOUSE_PORT`.

---

*Generated for AI agents to quickly understand and interact with the Gatehouse repository.*
