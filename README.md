# Gatehouse

**[gatehouse.to](https://gatehouse.to)**

A secrets vault built for AI agents, where credentials never leave the vault.

Traditional secret managers assume the client is trusted once authenticated. AI agents break that assumption. Their context windows get logged, cached, and sent to cloud APIs. A credential that enters an agent's memory can end up anywhere.

Gatehouse takes a different approach: **agents don't need to see your credentials at all.** With proxy mode, an agent says _"call this API for me"_ and gets back the response. The credential never enters the agent's address space, context window, or tool output. It can't be leaked because it was never there.

Because every proxy call flows through Gatehouse, it also **learns**. Successful requests are recorded as reusable API patterns: method, URL template, header names, request and response schemas, and confidence scored from a rolling window of recent outcomes. The next agent to touch that secret can ask Gatehouse _"how do I call this API?"_ and get back known-good templates verified by other agents, without burning tokens on trial-and-error or stale documentation.

For everything else (leasing, dynamic secrets, SSH certificates, audit logging) Gatehouse gives you Vault-grade capabilities in a single Docker container, no unsealing ceremony, no Consul cluster, no operational overhead.

## Why Gatehouse?

- **Credentials never touch the agent.** Proxy mode injects secrets into HTTP requests server-side. The agent gets the API response, not the key. This isn't a feature other vaults have.
- **APIs that teach themselves.** Every successful proxy call is recorded as a pattern (method, URL, header names, body schema) scored by confidence and multi-agent verification. New agents query `gatehouse_patterns` and learn how to call an API before spending a single token guessing.
- **Single Docker container.** No Consul, no Raft cluster, no unsealing ceremony. `docker run` and you're done.
- **AI-native interfaces.** MCP server (9 tools) for Claude Code, Codex, Windsurf, Cursor, OpenCode; REST API for everything else.
- **Dynamic secrets.** Ephemeral database credentials and SSH certificates that self-destruct on expiry. No static keys to rotate or revoke.
- **Per-agent identity.** Each agent gets its own AppRole with scoped policies and full audit trail.
- **Homelab-first.** Runs on a Raspberry Pi, Proxmox LXC, or Jetson Orin Nano. AGPL-3.0 licensed.
- **Beautiful web UI.** Dark-themed control panel for managing secrets, leases, agents, and audit logs.

## Core features

- **Encrypted KV store.** XSalsa20-Poly1305 envelope encryption, HKDF-SHA256 key derivation, SQLite at rest.
- **Credential leasing.** Agents check out secrets with TTLs, auto-revoke on expiry.
- **Proxy mode.** Agents send HTTP requests with secret references; Gatehouse injects credentials and forwards upstream. Agents never see raw keys. Domain allowlisting prevents exfiltration.
- **Pattern learning.** Successful proxy calls are auto-recorded as normalized templates (URL with `:id`/`:num` placeholders, header names, body key/type schemas). Patterns are scored by a rolling confidence window and tagged with the agents that verified them. On proxy failure, Gatehouse returns suggested known-good patterns in the error response. Operators can pin or delete patterns through the web UI. No secret values are ever stored in a pattern.
- **Dynamic secrets.** Vault-style temporary credential generation with 5 built-in providers: PostgreSQL, MySQL/MariaDB, MongoDB, Redis, and SSH certificates. Pluggable provider interface for custom backends. Configs encrypted at rest.
- **Key rotation.** Rotate the master key and re-wrap all DEKs + dynamic configs in one API call, zero downtime.
- **YAML + DB policies.** Path-based ACLs with glob matching. YAML for version control, DB for UI management. Capabilities: read, write, delete, list, lease, proxy, admin.
- **MCP server.** 9 tools including `gatehouse_proxy` for credential-injecting HTTP forwarding and `gatehouse_patterns` for querying learned API call templates.
- **REST API.** Standard HTTP for everything else, including credential scrubbing endpoint.
- **Audit log.** Structured JSON with configurable retention policy and automatic purge.
- **Output scrubbing.** Catch and redact leaked credentials before they hit agent context (MCP + REST).
- **TOTP two-factor auth.** Optional RFC 6238 TOTP for user accounts with one-time recovery codes. Self-service enrollment via the web UI; admins can force-reset a user's 2FA.
- **Security hardened.** HKDF key derivation, timing-safe token comparison, CORS restrictions, security headers (HSTS, X-Frame-Options, CSP).
- **OAuth + AppRole auth.** SSO integration for humans, token-based AppRole for machines.
- **Web UI.** Dark-themed control panel for managing secrets, leases, agents, policies, proxy, dynamic secrets, and audit logs.

## Quick start

```bash
docker run -d \
  --name gatehouse \
  -p 3100:3100 \
  -v gatehouse-data:/data \
  -v ./config:/config \
  -e GATEHOUSE_MASTER_KEY="$(openssl rand -hex 32)" \
  ghcr.io/bshandley/gatehouse:latest
```

See [Authentication](#authentication) below for how to get a token.

```bash
# Store a secret
curl -X POST http://localhost:3100/v1/secrets/openai \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value": "sk-proj-...", "metadata": {"service": "openai", "env": "prod"}}'

# Lease a secret (auto-expires after 300s)
curl -X POST http://localhost:3100/v1/lease/openai \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -d '{"ttl": 300}'

# Revoke a lease early
curl -X DELETE http://localhost:3100/v1/lease/abc123 \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN"
```

## Authentication

Gatehouse supports three auth methods: root token (bootstrapping only), user accounts (web UI), and AppRoles (agents).

**Giving an agent access?** Share [`docs/agent-api-reference.md`](docs/agent-api-reference.md) with it. That file is written for agents and covers auth, secret access, proxy mode, dynamic secrets, and error handling in a format they can follow directly.

### For agents: AppRole authentication

AppRoles are how agents authenticate. An admin creates an AppRole in the web UI or via the API, which produces a `role_id` and `secret_id`. The agent exchanges these for a JWT, then uses the JWT for all subsequent requests.

**Step 1: Admin creates an AppRole**

```bash
curl -X POST http://localhost:3100/v1/auth/approle \
  -H "Authorization: Bearer $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"display_name": "my-agent", "policies": ["agent-readonly"]}'
```

Response:

```json
{
  "role_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "secret_id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
  "display_name": "my-agent",
  "policies": ["agent-readonly"]
}
```

Save both values. The `secret_id` cannot be retrieved again.

**Step 2: Agent logs in with role_id + secret_id**

```bash
curl -X POST http://localhost:3100/v1/auth/approle/login \
  -H "Content-Type: application/json" \
  -d '{"role_id": "xxxxxxxx-...", "secret_id": "yyyyyyyy-..."}'
```

Response:

```json
{
  "token": "eyJhbGciOiJFUzI1NiIs...",
  "identity": "approle:my-agent",
  "policies": ["agent-readonly"],
  "expires_in": 86400
}
```

**Step 3: Agent uses the JWT for all API calls**

```bash
export GATEHOUSE_TOKEN="eyJhbGciOiJFUzI1NiIs..."

# Now use it for any request
curl http://localhost:3100/v1/secrets?prefix=api-keys/ \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN"
```

The JWT expires after 24 hours by default. The agent should re-login when it receives a 401 response.

### For humans: user accounts

Admins log into the web UI with a username and password. Create user accounts via the root token:

```bash
curl -X POST http://localhost:3100/v1/auth/users \
  -H "Authorization: Bearer $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password", "policies": ["admin"]}'
```

### Root token

Set `GATEHOUSE_ROOT_TOKEN` in the environment for initial setup. Use it to create AppRoles and user accounts, then unset it. The root token grants full access to everything and should not be used in production.

## Proxy mode

Agents send HTTP requests through Gatehouse with secret placeholders. Gatehouse resolves them, makes the upstream call, and returns the response. The agent never sees the raw credential.

Two injection styles:

```bash
# Template style: {{secret:path}} placeholders in headers/URL/body
curl -X POST http://localhost:3100/v1/proxy \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
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

# Inject shorthand: map header names to secret paths
curl -X POST http://localhost:3100/v1/proxy \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "POST",
    "url": "https://api.openai.com/v1/chat/completions",
    "inject": {"Authorization": "api-keys/openai"},
    "headers": {"Content-Type": "application/json"},
    "body": {"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}
  }'
```

**Domain allowlisting**: Set `allowed_domains` in a secret's metadata (e.g. `"api.openai.com,openai.com"`) to restrict which hosts that secret can be sent to. Prevents compromised agents from exfiltrating credentials to unauthorized domains.

## Pattern learning

Every successful proxy call is captured as a reusable API pattern. The next agent that touches the same secret can ask Gatehouse what known-good requests look like instead of guessing headers, URL formats, or body shapes. Agents stop burning context on stale documentation and API trial-and-error.

**What's recorded (on 2xx responses):**

- HTTP method and normalized URL template (`/users/:id`, `/memos/:num`, `/events/:date`)
- Request header **names** (never values)
- Request body **schema**: top-level keys and their types (`string`, `number`, `boolean`, `array<string>`, `object`)
- Response status and response body schema (same key/type format)
- A rolling window of the last 20 outcomes (success/failure per attempt)
- Which agent identities have verified the pattern

**What's never recorded:** secret values, raw credential bytes, request bodies, response bodies. Only schemas and header names.

**Confidence scoring:** `successes / total` across the rolling 20-outcome window, computed at query time. The `verified_by` count (distinct agents that have succeeded with the pattern) is reported alongside it, because multi-agent verification is a stronger signal than one agent calling the same endpoint 100 times.

**Query a pattern before making a call:**

```bash
curl "http://localhost:3100/v1/proxy/patterns?secret=api-keys/memos" \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN"
```

Returns patterns sorted by confidence. Each entry shows the method, URL template, required header names, request/response schema, confidence, verified-by count, and whether an operator has pinned it:

```json
{
  "patterns": [
    {
      "method": "POST",
      "url_template": "https://memos.example/api/v1/memos",
      "request_headers": ["Content-Type", "Authorization"],
      "request_body_schema": {"content": "string", "visibility": "string"},
      "response_status": 200,
      "response_body_schema": {"id": "number", "content": "string", "creatorId": "number"},
      "confidence": 0.95,
      "verified_by": 3,
      "total_successes": 47,
      "pinned": false
    }
  ]
}
```

**Auto-suggestions on failure.** When a proxy call returns 4xx/5xx, Gatehouse looks up patterns for the same secret (confidence > 0.5, or pinned) and returns up to 5 of them in the error response's `suggestions` array. Agents can correct their next attempt without a separate round trip.

**MCP tool.** Call `gatehouse_patterns` with `secret_path` from any MCP-enabled agent (Claude Code, Codex, Cursor, Windsurf, OpenCode, etc.) to get the same data. Same policy gate as the REST endpoint: requires `proxy` or `read` on the secret path.

**Operator control.** The **Patterns** tab in the web UI groups patterns by secret path with confidence bars, method badges, and expandable detail views showing request/response schemas, recent outcome timelines, and which agents verified each pattern. Admins can **pin** patterns (immune to low-confidence filtering) or **delete** them. There are no create or edit forms: patterns come from real proxy traffic only, so the library stays honest.

**Why this matters for agents.** Without pattern learning, the first time a new agent touches an API it has to:

1. Read documentation that may be stale
2. Guess the request format
3. Retry on 400s to figure out required fields
4. Burn context and wall time on trial and error

With pattern learning, the agent calls `gatehouse_patterns`, gets a verified template from an agent that already got it right, and makes its first attempt a working one. Each successful call makes the next agent faster.

## Dynamic secrets

Vault-style temporary credential generation. Instead of storing a static password, store admin connection details. Gatehouse creates short-lived credentials on demand and destroys them when the lease expires.

```bash
# Configure a PostgreSQL connection (admin only)
curl -X POST http://localhost:3100/v1/dynamic \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "db/postgres-prod",
    "provider_type": "postgresql",
    "config": {
      "host": "10.0.0.50",
      "port": "5432",
      "database": "myapp",
      "user": "postgres",
      "password": "admin-password",
      "grants": "SELECT,INSERT,UPDATE"
    }
  }'

# Agent checks out a temp credential (auto-revoked after TTL)
curl -X POST http://localhost:3100/v1/dynamic/db/postgres-prod/checkout \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -d '{"ttl": 600}'
# Returns: { "credential": { "username": "gh_agent1_abc123", "password": "...", "connection_string": "postgresql://..." }, "lease_id": "dlease-...", "expires_at": "..." }

# Revoke early (DROP ROLE at PostgreSQL)
curl -X DELETE http://localhost:3100/v1/dynamic/lease/dlease-xxx \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN"
```

Supported providers:

| Provider | Type | What it creates | What it revokes |
|----------|------|----------------|-----------------|
| **PostgreSQL** | `postgresql` | `CREATE ROLE` with scoped `GRANT` | `DROP ROLE` + kill connections |
| **MySQL/MariaDB** | `mysql` | `CREATE USER` with scoped `GRANT` | `DROP USER` + kill connections |
| **MongoDB** | `mongodb` | `createUser` with role-based access | `dropUser` + kill sessions |
| **Redis** | `redis` | `ACL SETUSER` with command/key scoping (Redis 6+) | `ACL DELUSER` |
| **SSH Certificates** | `ssh-cert` | Signs ephemeral keypair with CA (ed25519) | No-op (certs self-expire) |

The provider interface is pluggable. Add cloud IAM or custom backends by implementing `create`/`revoke`/`validate`.

### Provider setup guides

#### PostgreSQL

Store admin credentials. Gatehouse creates short-lived `CREATE ROLE` users scoped to specific `GRANT` privileges.

```bash
curl -X POST http://localhost:3100/v1/dynamic \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "db/postgres-prod",
    "provider_type": "postgresql",
    "config": {
      "host": "10.0.0.50",
      "port": "5432",
      "database": "myapp",
      "user": "postgres",
      "password": "admin-password",
      "grants": "SELECT,INSERT,UPDATE",
      "schema": "public"
    }
  }'
```

The admin user needs `CREATEROLE` privilege. On checkout, Gatehouse creates a role like `gh_agent1_abc123` with the specified grants. On revoke/expiry, the role is dropped and active connections killed.

#### MySQL / MariaDB

```bash
curl -X POST http://localhost:3100/v1/dynamic \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "db/mysql-prod",
    "provider_type": "mysql",
    "config": {
      "host": "10.0.0.51",
      "port": "3306",
      "database": "myapp",
      "user": "root",
      "password": "admin-password",
      "grants": "SELECT,INSERT,UPDATE"
    }
  }'
```

The admin user needs `CREATE USER` and `GRANT OPTION` privileges.

#### MongoDB

```bash
curl -X POST http://localhost:3100/v1/dynamic \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "db/mongo-prod",
    "provider_type": "mongodb",
    "config": {
      "url": "mongodb://admin:password@10.0.0.52:27017",
      "database": "myapp",
      "roles": "readWrite"
    }
  }'
```

The admin user needs the `userAdmin` role on the target database.

#### Redis

Requires Redis 6+ with ACL support.

```bash
curl -X POST http://localhost:3100/v1/dynamic \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "cache/redis-prod",
    "provider_type": "redis",
    "config": {
      "host": "10.0.0.53",
      "port": "6379",
      "password": "admin-password",
      "acl_rules": "+get +set +del ~app:*",
      "db": "0"
    }
  }'
```

The `acl_rules` field uses [Redis ACL syntax](https://redis.io/docs/management/security/acl/) to scope commands and key patterns.

#### SSH Certificates

Instead of distributing static SSH keys, Gatehouse signs short-lived certificates on demand. Agents get a fresh keypair + signed cert valid only for the requested TTL. No keys to rotate, no `authorized_keys` to manage.

**1. Generate a CA keypair** (do this once, keep the private key safe):

```bash
ssh-keygen -t ed25519 -f gatehouse_ca -N ""
# This creates gatehouse_ca (private) and gatehouse_ca.pub (public)
```

Or use the **"Generate New CA Keypair"** button in the web UI, which generates the keys for you and shows the host setup commands.

**2. Configure target hosts** to trust your CA. On each host you want agents to SSH into:

```bash
# Copy the CA public key to the host
scp gatehouse_ca.pub user@target-host:/etc/ssh/gatehouse_ca.pub

# Add to /etc/ssh/sshd_config:
TrustedUserCAKeys /etc/ssh/gatehouse_ca.pub

# Restart SSH
# Ubuntu/Debian:
sudo systemctl restart ssh
# RHEL/Arch:
# sudo systemctl restart sshd
```

**Important:** The CA public key goes in `/etc/ssh/gatehouse_ca.pub` and is referenced by `TrustedUserCAKeys` in `sshd_config`. It does **not** go in `~/.ssh/authorized_keys`. Certificate auth and key auth are separate mechanisms.

**3. Store the CA private key in Gatehouse** (via API or web UI):

```bash
curl -X POST http://localhost:3100/v1/dynamic \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "ssh/lab",
    "provider_type": "ssh-cert",
    "config": {
      "ca_private_key": "'"$(cat gatehouse_ca)"'",
      "principals": "ubuntu,deploy",
      "extensions": "permit-pty,permit-port-forwarding"
    }
  }'
```

Config fields:

| Field | Required | Description |
|-------|----------|-------------|
| `ca_private_key` | Yes | PEM-encoded CA private key (the signing authority) |
| `principals` | Yes | Comma-separated SSH usernames the cert is valid for (must match real users on target hosts) |
| `extensions` | No | Comma-separated cert extensions (default: `permit-pty`) |

**4. Agent checks out a signed certificate:**

```bash
curl -X POST http://localhost:3100/v1/dynamic/ssh/lab/checkout \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -d '{"ttl": 3600}'
```

Returns:
```json
{
  "lease_id": "dlease-abc123",
  "credential": {
    "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
    "public_key": "ssh-ed25519 AAAA...",
    "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
    "cert_id": "gh_agent1_abc123",
    "principals": "ubuntu,deploy",
    "valid_seconds": "3600",
    "ca_public_key": "ssh-ed25519 AAAA...",
    "usage": "Save all three files, then: ssh -i agent_key -o CertificateFile=agent_key-cert.pub user@host"
  },
  "expires_at": "2025-01-15T12:00:00Z"
}
```

**5. Agent uses the certificate to SSH:**

```bash
# Save the three files
echo "$PRIVATE_KEY" > agent_key && chmod 600 agent_key
echo "$CERTIFICATE" > agent_key-cert.pub

# Connect
ssh -i agent_key -o CertificateFile=agent_key-cert.pub ubuntu@target-host
```

The certificate is self-expiring. After the TTL, it's cryptographically invalid. No revocation needed, no remote state to clean up.

**Requires**: `ssh-keygen` must be installed on the Gatehouse host (included in the Docker image). The `principals` in the cert must match real usernames on the target hosts.

### Policies for dynamic secrets

Dynamic secrets only need two capabilities:

- **`lease`**: allows an agent to check out temporary credentials
- **`admin`**: allows managing configs (create/delete connections, test, view leases)

Example policy for an agent that can check out database and SSH credentials:

```yaml
name: infra-agent
rules:
  - path: "db/*"
    capabilities: [lease]
  - path: "ssh/*"
    capabilities: [lease]
```

The web UI automatically shows only relevant capabilities when a rule's paths are all dynamic secrets.

## Key rotation

Rotate the master key with zero downtime. All secret DEKs and dynamic configs are re-wrapped in a single atomic operation.

```bash
# Generate a new master key
NEW_KEY=$(openssl rand -hex 32)

# Rotate (re-wraps all DEKs + dynamic configs)
curl -X POST http://localhost:3100/v1/admin/rotate-key \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"new_master_key\": \"$NEW_KEY\"}"

# Then update GATEHOUSE_MASTER_KEY env var and restart
```

## Credential scrubbing

Scan text for leaked credentials (API keys, tokens, connection strings) via REST or MCP.

```bash
# Scrub text
curl -X POST http://localhost:3100/v1/scrub \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"text": "My key is sk-proj-abc123def456..."}'

# Quick boolean check
curl -X POST http://localhost:3100/v1/scrub/check \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"text": "some text to check"}'
```

## Audit log retention

Configure automatic cleanup of old audit entries.

```bash
# Set retention to 90 days (0 = keep forever)
curl -X POST http://localhost:3100/v1/audit/retention \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"retention_days": 90}'

# Manually purge old entries
curl -X POST http://localhost:3100/v1/audit/purge \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN"
```

## OpenClaw integration

```json
{
  "secrets": {
    "providers": {
      "gatehouse": {
        "source": "exec",
        "command": "curl",
        "args": ["-s", "-H", "Authorization: Bearer ${GATEHOUSE_TOKEN}", "http://gatehouse:3100/v1/secrets/openai/value"],
        "jsonOnly": false
      }
    }
  }
}
```

Or use the MCP server directly. Gatehouse registers as an MCP tool provider.

## Configuration reference

Every `GATEHOUSE_*` environment variable, what it does, and what you're trading off when you change it.

### Required

| Variable | Default | Description |
|---|---|---|
| `GATEHOUSE_MASTER_KEY` | *(none, required)* | 64-character hex string used to derive the KEK that wraps all secret DEKs. Generate with `openssl rand -hex 32`. If this value is lost, all encrypted secrets are unrecoverable. If it leaks, anyone with the database file can decrypt everything offline. |
| `GATEHOUSE_ROOT_TOKEN` | *(none)* | Bootstrap token for initial setup (creating users and AppRoles). This token bypasses all policy checks and has full admin access. **Remove it from your environment after creating your first user account and AppRoles.** Leaving it set is a persistent backdoor. |

### Networking and server

| Variable | Default | Description |
|---|---|---|
| `GATEHOUSE_PORT` | `3100` | HTTP listen port inside the container. |
| `GATEHOUSE_CORS_ORIGINS` | *(empty, restrictive)* | Comma-separated list of allowed CORS origins. Only needed if you access the web UI from a different origin than where Gatehouse is running (e.g., behind a reverse proxy on a different hostname). Example: `https://gatehouse.local,https://gatehouse.yourdomain.com`. When empty, CORS is restricted to same-origin requests only. |
| `GATEHOUSE_MAX_BODY_SIZE` | `1048576` (1 MB) | Maximum request body size in bytes. Increase this if your proxy payloads are larger than 1 MB (e.g., forwarding file uploads through the proxy). Setting this too high lets agents send arbitrarily large payloads through Gatehouse. |

### Proxy and SSRF

| Variable | Default | Description |
|---|---|---|
| `GATEHOUSE_PROXY_ALLOW_PRIVATE` | `false` | **This is the setting most homelabbers need to change.** By default, the proxy blocks all requests to private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, link-local, and IPv6 equivalents) to prevent SSRF attacks. In a homelab, your services *are* on private IPs, so the proxy won't work without enabling this. Set to `true` to allow proxying to private networks. **What you're opting into:** agents can reach anything on your LAN through Gatehouse, so your policy rules and domain allowlists on secrets are the only thing scoping what they can hit. The more surgical alternative is leaving this `false` and setting `allow_private=true` in the metadata of specific secrets that need LAN access. |

### Paths and storage

| Variable | Default | Description |
|---|---|---|
| `GATEHOUSE_DATA_DIR` | `/data` | Directory for the SQLite database file. In Docker, mount a volume here so data persists across container restarts. |
| `GATEHOUSE_CONFIG_DIR` | `/config` | Directory for YAML policy files. Mount read-only (`:ro`) in Docker. Policies here are loaded on startup and can be reloaded via the API. |

### Authentication

| Variable | Default | Description |
|---|---|---|
| `GATEHOUSE_JWT_SECRET` | *(derived from master key)* | Override the JWT signing secret. By default, it's derived from `GATEHOUSE_MASTER_KEY` via HKDF with domain separation, which is fine for single-instance deployments. You'd only set this if you need JWT tokens to survive a master key rotation (uncommon). |

### Logging

| Variable | Default | Description |
|---|---|---|
| `GATEHOUSE_LOG_LEVEL` | `info` | Controls stdout log verbosity. Options: `debug` (verbose, includes request details), `info` (startup, errors, audit), `error` (errors only). |

### OAuth / SSO (optional)

| Variable | Default | Description |
|---|---|---|
| `GATEHOUSE_OAUTH_ISSUER` | *(empty, disabled)* | OIDC issuer URL for SSO integration (e.g., PocketID, Authelia, Authentik). When set, enables "Sign in with SSO" on the login screen. |
| `GATEHOUSE_OAUTH_CLIENT_ID` | *(empty)* | OAuth client ID registered with your identity provider. |
| `GATEHOUSE_OAUTH_CLIENT_SECRET` | *(empty)* | OAuth client secret. |
| `GATEHOUSE_OAUTH_REDIRECT_URI` | *(empty)* | OAuth callback URL. Must be reachable by the user's browser. Example: `https://gatehouse.yourdomain.com/v1/auth/callback`. |

### MCP stdio mode

These are only used when running the MCP stdio transport directly (not the main server).

| Variable | Default | Description |
|---|---|---|
| `GATEHOUSE_TOKEN` | *(none)* | Pre-authenticated JWT or root token for the stdio MCP session. |
| `GATEHOUSE_IDENTITY` | `mcp-agent` | Identity string used in audit logs for stdio MCP sessions. |
| `GATEHOUSE_POLICIES` | `admin` | Comma-separated policy list for stdio MCP sessions. |

### Homelab quick reference

A typical homelab `docker-compose.yml` environment block:

```yaml
environment:
  - GATEHOUSE_MASTER_KEY=${GATEHOUSE_MASTER_KEY}       # openssl rand -hex 32
  - GATEHOUSE_ROOT_TOKEN=${GATEHOUSE_ROOT_TOKEN}       # remove after initial setup
  - GATEHOUSE_PROXY_ALLOW_PRIVATE=true                 # required for LAN proxying
  - GATEHOUSE_LOG_LEVEL=info
```

The `GATEHOUSE_PROXY_ALLOW_PRIVATE=true` line is the most common missing piece. Without it, any proxy request to a `192.168.x.x` or `10.x.x.x` address returns a 403 SSRF block.

## Security considerations

Gatehouse encrypts all secrets at rest using envelope encryption (per-secret DEK, wrapped by a KEK derived from `GATEHOUSE_MASTER_KEY`). However, encryption at rest only protects against one threat: someone stealing the database file alone. If an attacker has both the SQLite file **and** the master key, they can decrypt everything offline, bypassing all ACLs and audit logging.

### Protecting the master key

The `GATEHOUSE_MASTER_KEY` is the single most sensitive value in your deployment. An agent (or anyone) with access to it and the database file has full access to every secret.

Ways the master key can leak:
- `docker inspect gatehouse` exposes environment variables
- `/proc/<pid>/environ` on the host is readable by root
- `docker exec` into the container gives access to the process environment
- Plain-text `.env` files or `docker-compose.yml` on disk

**Recommendations:**
1. **Never give agents Docker socket access.** No `docker.sock` mounts, no Docker group membership. This is the most important rule.
2. **Don't give agents host filesystem access** to the Gatehouse data volume or config directory.
3. **Use Docker secrets** (or your platform's secret manager) for `GATEHOUSE_MASTER_KEY` instead of a plain environment variable in your compose file.
4. **Run Gatehouse on a separate host** from your agents if possible. Agents should only reach Gatehouse over the network via the API on port 3100.
5. **Unset `GATEHOUSE_ROOT_TOKEN`** after initial setup. Create AppRoles for agents and user accounts for humans, then remove the root token from your environment.

### Threat model summary

| Agent has... | Risk |
|---|---|
| Network access to port 3100 only | Safe: goes through auth + policy ACLs + audit log |
| Read access to the data volume | Low: database is encrypted, useless without the master key |
| Access to `docker inspect` or host `/proc` | **High**: can extract the master key and decrypt offline |
| Docker socket access | **Critical**: full control over the container and its environment |

For a typical homelab setup where agents run on the same machine, the key is ensuring agents **only** interact with Gatehouse through the HTTP API and never have elevated host or Docker access.

## Tech stack

- **Runtime**: Bun + Hono
- **Storage**: SQLite via bun:sqlite (WAL mode)
- **Encryption**: tweetnacl (XSalsa20-Poly1305), envelope encryption with per-secret DEK, HKDF-SHA256 key derivation with domain separation
- **Auth**: JWT tokens (jose), AppRole for machines, username/password for UI admins, timing-safe token comparison
- **MCP**: 9 tools via Streamable HTTP, SSE, or stdio transport (including `gatehouse_patterns` for API pattern discovery)
- **Dynamic secrets**: pg (node-postgres) for PostgreSQL temp credential lifecycle, configs encrypted at rest
- **Security**: HKDF key derivation, CORS restrictions, CSP/HSTS/X-Frame-Options headers, key rotation support
- **Container**: Single Dockerfile, ~50MB image

## License

AGPL-3.0. See [LICENSE](LICENSE) for the full text.
