# Gatehouse

A secrets vault built for AI agents, where credentials never touch the agent.

Traditional secret managers assume the client is trusted once authenticated. AI agents break that assumption. Their context windows get logged, cached, and sent to cloud APIs. A credential that enters an agent's memory can end up anywhere.

Gatehouse takes a different approach: **agents don't need to see your credentials at all.** With proxy mode, an agent says _"call this API for me"_ and gets back the response. The credential never enters the agent's address space, context window, or tool output. It can't be leaked because it was never there.

For everything else (leasing, dynamic secrets, SSH certificates, audit logging) Gatehouse gives you Vault-grade capabilities in a single Docker container, no unsealing ceremony, no Consul cluster, no operational overhead.

## Why Gatehouse?

- **Credentials never touch the agent.** Proxy mode injects secrets into HTTP requests server-side. The agent gets the API response, not the key. This isn't a feature other vaults have.
- **Single Docker container.** No Consul, no Raft cluster, no unsealing ceremony. `docker run` and you're done.
- **AI-native interfaces.** MCP server (8 tools) for Claude Code, Codex, Windsurf, Cursor, OpenCode; REST API for everything else.
- **Dynamic secrets.** Ephemeral database credentials and SSH certificates that self-destruct on expiry. No static keys to rotate or revoke.
- **Per-agent identity.** Each agent gets its own AppRole with scoped policies and full audit trail.
- **Homelab-first.** Runs on a Raspberry Pi, Proxmox LXC, or Jetson Orin Nano. AGPL-3.0 licensed.
- **Beautiful web UI.** Dark-themed control panel for managing secrets, leases, agents, and audit logs.

## Core features

- **Encrypted KV store.** XSalsa20-Poly1305 envelope encryption, HKDF-SHA256 key derivation, SQLite at rest.
- **Credential leasing.** Agents check out secrets with TTLs, auto-revoke on expiry.
- **Proxy mode.** Agents send HTTP requests with secret references; Gatehouse injects credentials and forwards upstream. Agents never see raw keys. Domain allowlisting prevents exfiltration.
- **Dynamic secrets.** Vault-style temporary credential generation with 5 built-in providers: PostgreSQL, MySQL/MariaDB, MongoDB, Redis, and SSH certificates. Pluggable provider interface for custom backends. Configs encrypted at rest.
- **Key rotation.** Rotate the master key and re-wrap all DEKs + dynamic configs in one API call, zero downtime.
- **YAML + DB policies.** Path-based ACLs with glob matching. YAML for version control, DB for UI management. Capabilities: read, write, delete, list, lease, proxy, admin.
- **MCP server.** 8 tools including `gatehouse_proxy` for credential-injecting HTTP forwarding.
- **REST API.** Standard HTTP for everything else, including credential scrubbing endpoint.
- **Audit log.** Structured JSON with configurable retention policy and automatic purge.
- **Output scrubbing.** Catch and redact leaked credentials before they hit agent context (MCP + REST).
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
- **MCP**: 8 tools via Streamable HTTP, SSE, or stdio transport
- **Dynamic secrets**: pg (node-postgres) for PostgreSQL temp credential lifecycle, configs encrypted at rest
- **Security**: HKDF key derivation, CORS restrictions, CSP/HSTS/X-Frame-Options headers, key rotation support
- **Container**: Single Dockerfile, ~50MB image

## License

AGPL-3.0. See [LICENSE](LICENSE) for the full text.
