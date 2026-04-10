# Gatehouse API Reference for AI Agents

This document is written for AI agents that need to authenticate with and use Gatehouse. It covers every step from login to secret access. All examples use `curl` but any HTTP client works.

**Base URL:** `http://<gatehouse-host>:3100`

## Authentication

You need a JWT token before you can do anything. Your operator gave you a `role_id` and `secret_id`. These are **login credentials for the vault itself**, not secret paths or secret values. Exchange them for a token:

```bash
curl -X POST http://localhost:3100/v1/auth/approle/login \
  -H "Content-Type: application/json" \
  -d '{"role_id": "YOUR_ROLE_ID", "secret_id": "YOUR_SECRET_ID"}'
```

Response:

```json
{
  "token": "eyJhbGciOi...",
  "identity": "approle:your-agent-name",
  "policies": ["agent-readonly"],
  "expires_in": 86400
}
```

Use the `token` value as a Bearer token in all subsequent requests:

```
Authorization: Bearer eyJhbGciOi...
```

The token expires after 24 hours. When you get a `401` response, re-login to get a fresh token.

## Important: secrets are accessed by path, not by ID

Secrets in Gatehouse have human-readable paths like `api-keys/openai` or `services/memos-token`. You always use the **path** in API URLs, never a UUID.

**Do not confuse `secret_id` with a secret path.** The `secret_id` from AppRole login is a vault credential (like a password). It is not a reference to a stored secret. After login, discard it from your working context. To find actual secrets, use `GET /v1/secrets?prefix=` (see "List available secrets" below).

## What you can do depends on your policy

Your AppRole has one or more policies that control which secret paths you can access and what operations you can perform. Common capabilities:

| Capability | What it allows |
|---|---|
| `read` | Read a secret's value |
| `list` | List secret paths under a prefix (note: `read` also grants listing) |
| `write` | Create or update secrets |
| `delete` | Delete secrets |
| `lease` | Check out a secret with a TTL (also used for dynamic secrets) |
| `proxy` | Use secrets through the HTTP proxy without seeing raw values |
| `admin` | Full access to configuration and management |

If you get `{"error": "Forbidden"}`, your policy does not grant the required capability on that path. Ask your operator to check your policy rules.

## Reading secrets

### List available secrets

```bash
# List everything you have access to
curl http://localhost:3100/v1/secrets?prefix= \
  -H "Authorization: Bearer $TOKEN"

# Or filter by prefix
curl http://localhost:3100/v1/secrets?prefix=api-keys/ \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "secrets": [
    {"path": "api-keys/openai", "version": 1, "created_at": "..."},
    {"path": "api-keys/anthropic", "version": 1, "created_at": "..."}
  ]
}
```

The response is automatically filtered to only show secrets you have `read` or `list` access to. Use an empty prefix to discover everything available to you.

### Get a secret's value

```bash
curl http://localhost:3100/v1/secrets/api-keys/openai/value \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "path": "api-keys/openai",
  "value": "sk-proj-abc123...",
  "version": 1
}
```

For plain text only (no JSON wrapper):

```bash
curl http://localhost:3100/v1/secrets/api-keys/openai/value \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: text/plain"
```

Requires `read` capability on the path.

### Get secret metadata (no value)

```bash
curl http://localhost:3100/v1/secrets/api-keys/openai \
  -H "Authorization: Bearer $TOKEN"
```

Returns path, version, metadata, and timestamps, but not the secret value.

## Leasing secrets

Leases give you temporary, tracked access to a secret. The lease auto-expires after the TTL, and all access is logged.

### Check out a lease

```bash
curl -X POST http://localhost:3100/v1/lease/api-keys/openai \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ttl": 300}'
```

TTL is in seconds (min: 10, max: 86400). Default: 300 (5 minutes).

Response:

```json
{
  "lease": {
    "id": "lease-xxxxxxxx",
    "path": "api-keys/openai",
    "expires_at": "2025-01-15T12:05:00Z"
  },
  "value": "sk-proj-abc123..."
}
```

Requires `lease` capability on the path.

### List your active leases

```bash
curl http://localhost:3100/v1/lease \
  -H "Authorization: Bearer $TOKEN"
```

### Revoke a lease early

```bash
curl -X DELETE http://localhost:3100/v1/lease/lease-xxxxxxxx \
  -H "Authorization: Bearer $TOKEN"
```

## Proxy mode (recommended)

Proxy mode lets you make HTTP requests through Gatehouse without ever seeing the raw credential. Gatehouse injects the secret server-side and returns the upstream response.

### Template style

Use `{{secret:path}}` placeholders anywhere in headers, URL, or body:

```bash
curl -X POST http://localhost:3100/v1/proxy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "POST",
    "url": "https://api.openai.com/v1/chat/completions",
    "headers": {
      "Authorization": "Bearer {{secret:api-keys/openai}}",
      "Content-Type": "application/json"
    },
    "body": {"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}
  }'
```

### Inject shorthand (recommended)

Map header names to secret paths. The value is **just the secret path**, not the full header value. Gatehouse auto-prefixes `Bearer ` for Authorization headers:

```bash
curl -X POST http://localhost:3100/v1/proxy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "POST",
    "url": "https://api.openai.com/v1/chat/completions",
    "inject": {"Authorization": "api-keys/openai"},
    "headers": {"Content-Type": "application/json"},
    "body": {"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}
  }'
```

Requires `proxy` capability on each secret path used.

### Common proxy mistakes

**Wrong: putting `Bearer` or the full header value in the inject map**
```json
{"inject": {"Authorization": "Bearer {services/my-token}"}}
```
Gatehouse treats the entire value as a secret path. Since no secret exists at path `Bearer {services/my-token}`, you get a Forbidden error.

**Right: just the path**
```json
{"inject": {"Authorization": "services/my-token"}}
```
Gatehouse looks up `services/my-token`, gets the raw value, and automatically adds `Bearer ` in front for Authorization headers.

### Proxying to private/local networks

By default, Gatehouse blocks proxy requests to private IP ranges (10.x, 192.168.x, localhost, etc.) to prevent SSRF attacks. If you need to proxy to a service on your local network, your operator needs to either:

- Set `GATEHOUSE_PROXY_ALLOW_PRIVATE=true` in Gatehouse's environment, or
- Add `allow_private: "true"` to the secret's metadata

If you see an error about "private/internal networks are blocked", ask your operator to enable this.

## Dynamic secrets

Dynamic secrets generate temporary credentials on demand (e.g., database users, SSH certificates). The credentials are automatically destroyed when the lease expires.

### Check out a dynamic credential

```bash
curl -X POST http://localhost:3100/v1/dynamic/db/postgres-prod/checkout \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ttl": 600}'
```

Response (varies by provider type):

```json
{
  "lease_id": "dlease-abc123",
  "path": "db/postgres-prod",
  "provider_type": "postgresql",
  "credential": {
    "username": "gh_myagent_abc123",
    "password": "random-generated-password",
    "host": "10.0.0.50",
    "port": "5432",
    "database": "myapp",
    "connection_string": "postgresql://gh_myagent_abc123:...@10.0.0.50:5432/myapp"
  },
  "ttl_seconds": 600,
  "expires_at": "2025-01-15T12:10:00Z"
}
```

Requires `lease` capability on the dynamic secret path.

### Revoke a dynamic lease early

```bash
curl -X DELETE http://localhost:3100/v1/dynamic/lease/dlease-abc123 \
  -H "Authorization: Bearer $TOKEN"
```

The provider-specific credential (database user, SSH cert, etc.) is destroyed immediately.

## Credential scrubbing

Before outputting text that might contain secrets, you can ask Gatehouse to redact them:

```bash
curl -X POST http://localhost:3100/v1/scrub \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"text": "The key is sk-proj-abc123..."}'
```

Response:

```json
{
  "scrubbed": "The key is sk-pro***REDACTED***",
  "redactions": [{"type": "openai_key", "count": 1}]
}
```

## Discovering API call patterns

Before making your first proxy call to an unfamiliar API, check if other agents have already figured out the correct request format:

```bash
curl http://localhost:3100/v1/proxy/patterns?secret=services/memos-token \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "patterns": [
    {
      "method": "POST",
      "url_template": "https://memos.example/api/v1/memos",
      "host": "memos.example",
      "request_headers": ["Content-Type", "Authorization"],
      "request_body_schema": {"content": "string", "visibility": "string"},
      "response_status": 200,
      "response_body_schema": {"id": "number", "content": "string"},
      "confidence": 0.95,
      "verified_by": 3,
      "total_successes": 47,
      "total_failures": 2,
      "last_used": "2026-04-09T..."
    }
  ]
}
```

Patterns are learned automatically from real proxy traffic. When you make a successful proxy call, Gatehouse records the normalized request template (no secret values, just the structure). High-confidence patterns have been verified by multiple agents over many calls.

If your proxy call fails, Gatehouse will include a `suggestions` field in the error response with known-good patterns for that secret. You don't need to query the patterns endpoint separately when handling errors.

Requires `proxy` or `read` capability on the secret path.

**MCP:** Use the `gatehouse_patterns` tool with `secret_path` to get the same data.

## Error responses

All errors follow this format:

```json
{
  "error": "Human-readable error message",
  "request_id": "uuid-for-debugging"
}
```

Common HTTP status codes:

| Code | Meaning |
|---|---|
| 400 | Bad request (invalid input, missing fields) |
| 401 | Unauthorized (missing or expired token, re-login needed) |
| 403 | Forbidden (valid token, but policy does not allow this action on this path) |
| 404 | Not found (secret path does not exist) |
| 502 | Provider error (dynamic secret backend unreachable) |

## MCP interface

If your harness supports MCP (Model Context Protocol), you can use Gatehouse as an MCP tool server instead of calling the REST API directly.

**Endpoint:** `POST /v1/mcp` (Streamable HTTP transport)

**Auth:** Same `Authorization: Bearer <JWT>` header as the REST API.

**Protocol:** JSON-RPC 2.0. Method names follow the MCP standard:

| Method | Description |
|---|---|
| `initialize` | Handshake, returns server capabilities |
| `tools/list` | List available tools |
| `tools/call` | Call a tool by name |

**Available tools:**

| Tool name | What it does |
|---|---|
| `gatehouse_get` | Read a secret value |
| `gatehouse_put` | Store/update a secret |
| `gatehouse_list` | List secret paths |
| `gatehouse_lease` | Check out a secret with TTL |
| `gatehouse_revoke` | Revoke an active lease |
| `gatehouse_scrub` | Redact credentials from text |
| `gatehouse_proxy` | Forward HTTP request with secret injection |
| `gatehouse_patterns` | Query learned API call patterns for a secret |
| `gatehouse_status` | Health check and identity info |

Most agent harnesses handle the MCP protocol automatically. See `docs/integrations.md` for harness-specific setup (Claude Code, Codex, Windsurf, Cursor, etc.).

## Quick start checklist

1. Get your `role_id` and `secret_id` from your operator (these are login credentials, not secret paths)
2. `POST /v1/auth/approle/login` with both values to get a JWT
3. Use the JWT as `Authorization: Bearer <token>` on all requests
4. `GET /v1/secrets?prefix=` to discover all secrets you have access to
5. `GET /v1/proxy/patterns?secret=<path>` to see known-good API call patterns for a secret
6. `GET /v1/secrets/<path>/value` to read a secret, or `POST /v1/proxy` to use it without seeing it
7. Re-login when you get a 401
