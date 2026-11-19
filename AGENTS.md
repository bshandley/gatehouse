# AGENTS.md

## Overview

`gatehouse` is a self‑hosted secrets vault for AI agents. It provides an HTTP API (MCP) that agents authenticate to using AppRole credentials and a JWT. Agents can read, list, write, delete, lease, or proxy secrets depending on their policies.

## Quick Start for Agents

1. **Onboard** – fetch the onboarding markdown provided by the operator:
   ```bash
   curl -fsSL "https://gatehouse.example/v1/onboard/<token>" > /tmp/onboard.md && cat /tmp/onboard.md
   ```
   Follow the instructions to exchange the bootstrap token for `role_id`, `secret_id` and a JWT.
2. **Store credentials** – set environment variables for the runtime:
   ```bash
   export GATEHOUSE_ROLE_ID=...
   export GATEHOUSE_SECRET_ID=...
   export GATEHOUSE_TOKEN=...
   ```
3. **Refresh token** (optional, for long‑running agents):
   ```bash
   curl -X POST http://localhost:3100/v1/auth/refresh \
     -H "Authorization: Bearer $GATEHOUSE_TOKEN"
   ```
   Replace `$GATEHOUSE_TOKEN` with the new token from the response.

## Core API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/auth/approle/login` | POST | Exchange `role_id`/`secret_id` for a JWT. |
| `/v1/auth/refresh` | POST | Refresh a still‑valid JWT (24 h TTL). |
| `/v1/auth/whoami` | GET | Inspect the current token (identity, policies, expiry). |
| `/v1/secrets` | GET | List secret paths you can access (`?prefix=` optional). |
| `/v1/secrets/:path` | GET | Read a secret's value (requires `read` capability). |
| `/v1/secrets/:path` | PUT | Create or update a secret (requires `write`). |
| `/v1/secrets/:path` | DELETE | Delete a secret (requires `delete`). |
| `/v1/lease/:path` | POST | Lease a dynamic secret (requires `lease`). |
| `/v1/proxy/:path` | ANY | Proxy a request through Gatehouse without exposing the raw secret (requires `proxy`). |
| `/v1/skill` | GET | Fetch the installed skill markdown for the agent’s policies. |

## Policy‑Based Capabilities

Agents are assigned one or more policies (see `config/policies/*.yaml`). The most common capabilities are:

- `read` – fetch secret values.
- `list` – enumerate secret paths under a prefix.
- `write` – create or update secrets.
- `delete` – remove secrets.
- `lease` – obtain time‑limited dynamic secrets.
- `proxy` – make HTTP calls using the secret without ever seeing the raw value.
- `admin` – full management rights (rare for agents).

If an API call returns `{"error":"Forbidden"}` the agent’s policy does not grant the needed capability.

## Secret Discovery Patterns

When listing secrets the response includes two helpful fields:

- `pattern_count` – how many verified request shapes exist for this secret.
- `top_pattern` – a representative `METHOD url_template` that works out‑of‑the‑box.

If `pattern_count > 0` retrieve the full pattern via:
```bash
curl http://localhost:3100/v1/proxy/patterns?secret=<path> \
  -H "Authorization: Bearer $TOKEN"
```
Use the returned method, URL, headers and body schema to call the secret without trial‑and‑error.

If `pattern_count == 0` fall back to `metadata.allowed_domains` to discover the host you may contact; the first successful proxy call will seed a pattern for downstream agents.

## Development Workflow (for contributors)

- **Build** – `bun run dev` watches TypeScript sources.
- **Test** – `bun test` runs the full Jest‑style suite under `test/`.
- **Database migration** – `bun run src/db/migrate.ts` (if schema changes).
- **Site docs** – `cd site && bun run dev` builds the static documentation site.

## Gotchas & Tips

- The JWT expires after 24 h; always handle `401` by refreshing or re‑logging in.
- `secret_id` is a credential, **not** a secret path – discard it after login.
- Proxy mode never returns the secret value; it streams the request/response through the vault.
- Policies are defined in `config/policies/*.yaml`; adding a new capability requires updating those files and reloading the server.
- All API URLs are relative to the base URL (`http://<host>:3100`). Adjust the host/port via the `BASE_URL` environment variable if needed.

---

*Generated for AI agents to quickly understand and interact with the Gatehouse repository.*