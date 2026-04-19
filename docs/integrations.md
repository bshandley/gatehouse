# Integrating Gatehouse with agent harnesses

Gatehouse exposes two MCP transports and a REST API. Every major agent harness
can connect to at least one of them. Pick the method that fits your setup.

| Transport           | Best for                                        |
|---------------------|-------------------------------------------------|
| MCP Streamable HTTP | Windsurf, Cursor, OpenCode, remote agents       |
| MCP stdio           | Claude Code, Codex CLI, OpenClaw, Hermes        |
| REST API            | Scripts, CI/CD, custom tooling, direct `curl`   |

---

## 1. Claude Code

Claude Code supports MCP servers via `.claude/settings.json` or the `claude mcp` CLI.

### Option A: stdio transport (recommended for local)

```bash
# Register Gatehouse as an MCP server
claude mcp add gatehouse \
  --transport stdio \
  -- bun run /path/to/gatehouse/src/mcp-stdio.ts

# Or with Docker
claude mcp add gatehouse \
  --transport stdio \
  -- docker run --rm -i \
    -v gatehouse-data:/data \
    -v /path/to/config:/config:ro \
    -e GATEHOUSE_MASTER_KEY=$GATEHOUSE_MASTER_KEY \
    -e GATEHOUSE_ROOT_TOKEN=$GATEHOUSE_ROOT_TOKEN \
    gatehouse:latest src/mcp-stdio.ts
```

### Option B: HTTP transport (Gatehouse running as a service)

Add to `.claude/settings.json`:
```json
{
  "mcpServers": {
    "gatehouse": {
      "url": "http://gatehouse.local:3100/v1/mcp",
      "headers": {
        "Authorization": "Bearer ${GATEHOUSE_TOKEN}"
      }
    }
  }
}
```

### Usage in Claude Code

Once connected, Claude can call Gatehouse tools naturally:
```
> Use gatehouse to get the OpenAI API key from api-keys/openai
> Lease the GitHub token from git/github-pat for 10 minutes
> List all available secrets under api-keys/
```

---

## 2. OpenAI Codex CLI

Codex supports MCP servers via `~/.codex/config.toml`.

### Option A: stdio transport

```toml
[mcp_servers.gatehouse]
command = ["bun", "run", "/path/to/gatehouse/src/mcp-stdio.ts"]
env = [
  "GATEHOUSE_MASTER_KEY=<your-key>",
  "GATEHOUSE_DATA_DIR=/path/to/data",
  "GATEHOUSE_CONFIG_DIR=/path/to/config",
  "GATEHOUSE_ROOT_TOKEN=<your-token>"
]
```

### Option B: HTTP transport

```toml
[mcp_servers.gatehouse]
url = "http://gatehouse.local:3100/v1/mcp"
env_key = "GATEHOUSE_TOKEN"
```

### Environment variable safety

Add Gatehouse credentials to Codex's env policy to prevent leaking:
```toml
[shell_environment_policy]
exclude = ["GATEHOUSE_MASTER_KEY", "GATEHOUSE_ROOT_TOKEN"]
```

---

## 3. Windsurf (Cascade)

Windsurf supports MCP via `~/.codeium/windsurf/mcp_config.json`.

### Streamable HTTP (recommended)

```json
{
  "mcpServers": {
    "gatehouse": {
      "serverUrl": "http://gatehouse.local:3100/v1/mcp",
      "headers": {
        "Authorization": "Bearer <your-gatehouse-token>"
      }
    }
  }
}
```

### SSE transport

```json
{
  "mcpServers": {
    "gatehouse": {
      "serverUrl": "http://gatehouse.local:3100/v1/mcp/sse"
    }
  }
}
```

After adding, restart Windsurf. Gatehouse tools will appear in the MCP panel.
Gatehouse exposes 8 tools - well under Windsurf's 100-tool limit.

---

## 4. Cursor

Add to `.cursor/mcp.json` (project-level) or `~/.cursor/mcp.json` (global):

```json
{
  "mcpServers": {
    "gatehouse": {
      "url": "http://gatehouse.local:3100/v1/mcp",
      "headers": {
        "Authorization": "Bearer <your-gatehouse-token>"
      }
    }
  }
}
```

Or use stdio:
```json
{
  "mcpServers": {
    "gatehouse": {
      "command": "bun",
      "args": ["run", "/path/to/gatehouse/src/mcp-stdio.ts"],
      "env": {
        "GATEHOUSE_MASTER_KEY": "<your-key>",
        "GATEHOUSE_ROOT_TOKEN": "<your-token>"
      }
    }
  }
}
```

---

## 5. OpenCode

Add to your OpenCode config (`opencode.json` or `opencode.yaml`):

### Remote HTTP
```json
{
  "mcp": {
    "servers": {
      "gatehouse": {
        "type": "remote",
        "url": "http://gatehouse.local:3100/v1/mcp",
        "headers": {
          "Authorization": "Bearer <your-gatehouse-token>"
        }
      }
    }
  }
}
```

### Local stdio
```json
{
  "mcp": {
    "servers": {
      "gatehouse": {
        "type": "local",
        "command": ["bun", "run", "/path/to/gatehouse/src/mcp-stdio.ts"],
        "env": {
          "GATEHOUSE_MASTER_KEY": "<your-key>",
          "GATEHOUSE_ROOT_TOKEN": "<your-token>"
        }
      }
    }
  }
}
```

---

## 6. OpenClaw

OpenClaw has the most flexible secrets integration. You can use Gatehouse as
both an MCP tool provider AND a secrets backend.

### As an MCP server (recommended)

```bash
openclaw mcp add gatehouse --transport sse \
  --url http://gatehouse.local:3100/v1/mcp/sse
```

### As a secrets exec provider

In `openclaw.json`:
```json
{
  "secrets": {
    "providers": {
      "gatehouse": {
        "source": "exec",
        "command": "curl",
        "args": [
          "-s", "-H", "Authorization: Bearer ${GATEHOUSE_TOKEN}",
          "-H", "Accept: text/plain",
          "http://gatehouse.local:3100/v1/secrets/${id}/value"
        ],
        "jsonOnly": false
      }
    }
  },
  "models": {
    "providers": {
      "anthropic": {
        "apiKey": {
          "source": "exec",
          "provider": "gatehouse",
          "id": "api-keys/anthropic"
        }
      },
      "openai": {
        "apiKey": {
          "source": "exec",
          "provider": "gatehouse",
          "id": "api-keys/openai"
        }
      }
    }
  }
}
```

This means OpenClaw never stores API keys locally - it fetches them from
Gatehouse at runtime, with full audit logging.

---

## 7. Hermes Agent

Hermes uses `.hermes/.env` for credentials. Replace static values with
Gatehouse lookups in your shell profile or startup script:

```bash
# ~/.hermes/startup.sh (source this before launching Hermes)
export OPENAI_API_KEY=$(curl -s \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Accept: text/plain" \
  http://gatehouse.local:3100/v1/secrets/api-keys/openai/value)

export ANTHROPIC_API_KEY=$(curl -s \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Accept: text/plain" \
  http://gatehouse.local:3100/v1/secrets/api-keys/anthropic/value)
```

Or register Gatehouse as an MCP server in Hermes's config.

---

## 8. Roo Code / Kilo Code / Cline / Aider

All VS Code-based agent extensions support MCP via their settings files.
The pattern is identical to Cursor:

```json
{
  "mcpServers": {
    "gatehouse": {
      "url": "http://gatehouse.local:3100/v1/mcp",
      "headers": {
        "Authorization": "Bearer <your-gatehouse-token>"
      }
    }
  }
}
```

---

## 9. Docker containers / CI/CD

For non-MCP consumers (scripts, containers, GitLab CI, GitHub Actions):

```bash
# Fetch a secret
SECRET=$(curl -s \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Accept: text/plain" \
  http://gatehouse.local:3100/v1/secrets/api-keys/openai/value)

# Lease a secret (auto-expires)
LEASE=$(curl -s -X POST \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ttl": 600}' \
  http://gatehouse.local:3100/v1/lease/api-keys/openai)

# Extract value from lease response
VALUE=$(echo $LEASE | jq -r '.value')
LEASE_ID=$(echo $LEASE | jq -r '.lease.id')

# ... do work ...

# Revoke when done
curl -s -X DELETE \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  http://gatehouse.local:3100/v1/lease/$LEASE_ID
```

---

## Per-agent identity setup

The real power of Gatehouse is giving each agent its own identity and access scope.

```bash
# Create an AppRole for OpenClaw (read-only API keys, can lease)
curl -X POST http://localhost:3100/v1/auth/approle \
  -H "Authorization: Bearer $GATEHOUSE_ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "openclaw-prod",
    "policies": ["agent-readonly"]
  }'
# Returns: { "role_id": "role-xxx", "secret_id": "yyy" }
# Save the secret_id - it's shown only once.

# Create a separate AppRole for Codex (coding agent with broader access)
curl -X POST http://localhost:3100/v1/auth/approle \
  -H "Authorization: Bearer $GATEHOUSE_ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "codex-desktop",
    "policies": ["coding-agent"]
  }'

# Exchange AppRole credentials for a JWT
curl -X POST http://localhost:3100/v1/auth/approle/login \
  -H "Content-Type: application/json" \
  -d '{"role_id": "role-xxx", "secret_id": "yyy"}'
# Returns: { "token": "<jwt>", "identity": "approle:openclaw-prod", ... }
```

Now OpenClaw can only access `api-keys/*` and `services/*`, while Codex
can also access `db/*` and `git/*`. The audit log shows exactly which
agent accessed which secret, when.

---

## Proxy mode

Instead of giving agents raw API keys, route their HTTP requests through Gatehouse.
The agent constructs the request but never sees the credential - Gatehouse injects
it server-side.

### MCP (recommended for agents)

Agents can call `gatehouse_proxy` directly:

```
> Use gatehouse_proxy to call the OpenAI chat completions API with api-keys/openai
```

The tool supports two injection styles:

**Template style** - `{{secret:path}}` placeholders in headers, URL, or body:
```json
{
  "method": "POST",
  "url": "https://api.openai.com/v1/chat/completions",
  "headers": {
    "Authorization": "Bearer {{secret:api-keys/openai}}",
    "Content-Type": "application/json"
  },
  "body": {"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}
}
```

**Inject shorthand** - map header names to secret paths:
```json
{
  "method": "POST",
  "url": "https://api.openai.com/v1/chat/completions",
  "inject": {"Authorization": "api-keys/openai"},
  "headers": {"Content-Type": "application/json"},
  "body": {"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}
}
```

The inject shorthand auto-prefixes `Bearer ` for Authorization headers (unless
the secret value already starts with a scheme like `Bearer`, `Basic`, or `Token`).

### REST API

```bash
curl -X POST http://gatehouse.local:3100/v1/proxy \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "https://api.openai.com/v1/models",
    "inject": {"Authorization": "api-keys/openai"}
  }'
```

### Policy

Proxy access uses the `proxy` capability, separate from `read` and `lease`:

```yaml
name: proxy-only
rules:
  - path: "api-keys/*"
    capabilities: [proxy]
```

An agent with `proxy` but not `read` can use secrets through the proxy without
ever retrieving the raw value.

### Domain allowlisting

Set `allowed_domains` in a secret's metadata to restrict which hosts the secret
can be forwarded to:

```bash
curl -X POST http://gatehouse.local:3100/v1/secrets/api-keys/openai \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -d '{"value": "sk-...", "metadata": {"allowed_domains": "api.openai.com,openai.com"}}'
```

If an agent tries to proxy this secret to `evil.com`, Gatehouse blocks it with a 403.

---

## Dynamic secrets

For databases and other backends that support programmatic credential creation,
Gatehouse can create temporary credentials on demand - no static passwords needed.

### Setting up PostgreSQL dynamic secrets

1. **Configure the connection** (admin):

```bash
curl -X POST http://gatehouse.local:3100/v1/dynamic \
  -H "Authorization: Bearer $GATEHOUSE_ROOT_TOKEN" \
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

2. **Test the connection**:

```bash
curl -X POST http://gatehouse.local:3100/v1/dynamic/db/postgres-prod/validate \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN"
# Returns: { "ok": true }
```

3. **Agent checks out a temp credential**:

```bash
curl -X POST http://gatehouse.local:3100/v1/dynamic/db/postgres-prod/checkout \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -d '{"ttl": 600}'
```

Returns:
```json
{
  "lease_id": "dlease-abc123",
  "credential": {
    "username": "gh_agent1_abc123",
    "password": "random-generated-password",
    "host": "10.0.0.50",
    "port": "5432",
    "database": "myapp",
    "connection_string": "postgresql://gh_agent1_abc123:...@10.0.0.50:5432/myapp"
  },
  "expires_at": "2025-01-15 12:10:00"
}
```

4. **Credential auto-revokes** when the TTL expires (Gatehouse runs `DROP ROLE`).
   Or revoke early:

```bash
curl -X DELETE http://gatehouse.local:3100/v1/dynamic/lease/dlease-abc123 \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN"
```

### How it works under the hood

- Gatehouse connects to PostgreSQL using the admin credentials
- `CREATE ROLE gh_<identity>_<random> WITH LOGIN PASSWORD '...' VALID UNTIL '...'`
- Grants configured privileges on the specified schema
- On revoke: `pg_terminate_backend()` + `REVOKE ALL` + `DROP ROLE`

### MySQL / MariaDB

```bash
curl -X POST http://gatehouse.local:3100/v1/dynamic \
  -H "Authorization: Bearer $GATEHOUSE_ROOT_TOKEN" \
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

Creates `CREATE USER` with parameterized grants. On revoke: kills connections, `DROP USER IF EXISTS`, `FLUSH PRIVILEGES`. Admin user needs `CREATE USER` and `GRANT OPTION`.

### MongoDB

```bash
curl -X POST http://gatehouse.local:3100/v1/dynamic \
  -H "Authorization: Bearer $GATEHOUSE_ROOT_TOKEN" \
  -d '{
    "path": "db/mongo-prod",
    "provider_type": "mongodb",
    "config": {
      "host": "10.0.0.52",
      "port": "27017",
      "database": "myapp",
      "user": "admin",
      "password": "admin-password",
      "roles": "readWrite"
    }
  }'
```

Creates `createUser` with role-scoped access. On revoke: kills sessions via `currentOp`, `dropUser`. Admin user needs `userAdmin` or `userAdminAnyDatabase` role.

### Redis

```bash
curl -X POST http://gatehouse.local:3100/v1/dynamic \
  -H "Authorization: Bearer $GATEHOUSE_ROOT_TOKEN" \
  -d '{
    "path": "cache/redis-prod",
    "provider_type": "redis",
    "config": {
      "host": "10.0.0.53",
      "port": "6379",
      "password": "admin-password",
      "commands": "+@read +@write",
      "keys": "~myapp:*"
    }
  }'
```

Creates `ACL SETUSER` with scoped commands and key patterns. On revoke: `ACL DELUSER` (automatically disconnects sessions). Requires Redis 6+ with ACL support.

### SSH Certificates

```bash
curl -X POST http://gatehouse.local:3100/v1/dynamic \
  -H "Authorization: Bearer $GATEHOUSE_ROOT_TOKEN" \
  -d '{
    "path": "ssh/prod-servers",
    "provider_type": "ssh-cert",
    "config": {
      "ca_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
      "principals": "ubuntu,deploy",
      "extensions": "permit-pty,permit-port-forwarding"
    }
  }'
```

Generates an ephemeral ed25519 keypair and signs it with the CA key using `ssh-keygen`. Returns `private_key`, `public_key`, `certificate`, and usage instructions. Certs self-expire via the built-in validity window - no revocation needed.

**Server-side setup:**
1. Generate CA: `ssh-keygen -t ed25519 -f gatehouse_ca -N ""`
2. Store the private key contents as `ca_private_key` in the config above
3. On target hosts, add to `/etc/ssh/sshd_config`: `TrustedUserCAKeys /etc/ssh/gatehouse_ca.pub`
4. Copy `gatehouse_ca.pub` to each target host

### Policy

Dynamic secrets use the `lease` capability, same as regular lease checkout:

```yaml
name: db-agent
rules:
  - path: "db/*"
    capabilities: [lease]
```

---

## Credential scrubbing

Gatehouse can scan text for leaked credentials and redact them. Available via
MCP (`gatehouse_scrub`) and REST API.

### REST API

```bash
# Scrub text - returns redacted version + list of what was found
curl -X POST http://gatehouse.local:3100/v1/scrub \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"text": "My OpenAI key is sk-proj-abc123..."}'
# Returns: { "scrubbed": "My OpenAI key is sk-pro***REDACTED***", "redactions": [...] }

# Quick check - just returns whether credentials were detected
curl -X POST http://gatehouse.local:3100/v1/scrub/check \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"text": "some text to check"}'
# Returns: { "contains_credentials": false }
```

Detects: OpenAI keys, Anthropic keys, GitHub PATs, AWS credentials, Stripe keys,
Slack tokens, bearer tokens, basic auth URLs, private keys, and connection strings.

---

## Key rotation

Rotate the master key without downtime. All secret DEKs and encrypted dynamic
configs are re-wrapped atomically.

```bash
# Generate a new key
NEW_KEY=$(openssl rand -hex 32)

# Rotate
curl -X POST http://gatehouse.local:3100/v1/admin/rotate-key \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"new_master_key\": \"$NEW_KEY\"}"

# Update your env var and restart Gatehouse
export GATEHOUSE_MASTER_KEY=$NEW_KEY
```

---

## Audit log retention

Configure how long audit entries are kept. Gatehouse runs an hourly background
purge; you can also trigger it manually.

```bash
# Set retention to 90 days (0 = keep forever)
curl -X POST http://gatehouse.local:3100/v1/audit/retention \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"retention_days": 90}'

# View current retention config + entry count
curl http://gatehouse.local:3100/v1/audit/retention \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN"

# Manually purge now
curl -X POST http://gatehouse.local:3100/v1/audit/purge \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN"
```
