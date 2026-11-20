# Integrating Gatehouse with agent harnesses

Gatehouse exposes two MCP transports and a REST API. Every major agent harness
can connect to at least one of them. Pick the method that fits your setup.

| Transport           | Best for                                        |
|---------------------|-------------------------------------------------|
| MCP Streamable HTTP | Windsurf, Cursor, OpenCode, remote agents       |
| MCP stdio           | Claude Code, Codex CLI, OpenClaw, Hermes        |
| REST API            | Scripts, CI/CD, custom tooling, direct `curl`   |

Every stdio example below opens the vault directly, so it needs the data directory (`GATEHOUSE_DATA_DIR`, `/data` in the image) and a master key. `GATEHOUSE_MASTER_KEY` can be omitted when the data dir holds `master.key`, which is what a default install generates. The stdio entry exits with an error if it finds neither, and it never creates a key.

---

## 0. Onboarding links (fastest way to hand credentials to an agent)

If you don't want to copy-paste `role_id` / `secret_id` into chat yourself, let the agent install itself. Generate an onboarding link from the AppRole's **Onboard** action in the web UI (TTL 5 min to 1 hour), then paste the generated prompt to the agent over any channel:

```
Run this in your shell, then follow the instructions in the output:

curl -fsSL "https://gatehouse.example/v1/onboard/<token>" > /tmp/gatehouse-onboard.md
cat /tmp/gatehouse-onboard.md
```

The fetched markdown detects the harness (Hermes, OpenClaw, Claude Code, Pi, Codex/Cursor/Windsurf, or "no filesystem" fallback), calls `POST /v1/onboard/<token>/exchange` to receive rotated AppRole credentials and a 24h JWT, persists the env vars into the harness's credential path, and installs a `gatehouse` skill. Exchange is single-use and rotates the AppRole's `secret_id` - any agent already holding the previous `secret_id` will need to re-onboard.

Behind a reverse proxy? Set `GATEHOUSE_PUBLIC_URL=https://gatehouse.yourdomain.com` so the generated links use the public origin instead of whatever `Host` header Hono observes.

Every harness-specific section below still applies once the link is exchanged; the onboarding markdown writes the same env vars the manual flow would.

---

## 1. Claude Code

Claude Code supports MCP servers via `.claude/settings.json` or the `claude mcp` CLI.

### Option A: stdio transport (recommended for local)

```bash
# With Docker, against a default install (the gatehouse-data volume holds master.key)
claude mcp add --transport stdio gatehouse \
  -- docker run --rm -i \
    -v gatehouse-data:/data \
    -e GATEHOUSE_POLICIES=agent-readonly \
    ghcr.io/bshandley/gatehouse:latest mcp

# Or from a checkout, pointing at the data directory
claude mcp add --transport stdio \
  --env GATEHOUSE_DATA_DIR=/path/to/data \
  --env GATEHOUSE_POLICIES=agent-readonly \
  gatehouse -- bun run /path/to/gatehouse/src/mcp-stdio.ts
```

If the key lives in the environment instead of `master.key`, forward it by name: add `-e GATEHOUSE_MASTER_KEY` to the `docker run` (the value is taken from your shell), or `--env GATEHOUSE_MASTER_KEY=...` to the checkout form. To load policy files, mount your config directory with `-v /path/to/config:/config:ro`.

**`GATEHOUSE_POLICIES` is required.** It names the policies the agent on the other end may use, comma-separated (`agent-readonly` above is an example: use one you created in the UI, or a YAML policy under your config dir). There is no default. With neither `GATEHOUSE_POLICIES` nor `GATEHOUSE_TOKEN` set, the stdio server refuses to start, so an agent never gets the whole vault because a variable was left out. Full access means writing `GATEHOUSE_POLICIES=admin` on purpose. Names resolve against the same policies the server uses; an unknown name grants nothing and logs a warning. The identity recorded in the audit log is `GATEHOUSE_IDENTITY` (default `mcp-agent`).

The policy limits what the agent can do through the tools. It does not hide the master key: in stdio mode the key is on the same machine as the agent, and an agent with shell access may be able to read it. For a boundary the agent cannot step around, run Gatehouse as a service and use the HTTP transport with an AppRole. If you do set `GATEHOUSE_TOKEN`, it is verified like an HTTP bearer token (root token or a Gatehouse JWT) and the entry runs as that identity; a token that does not verify makes it exit. JWTs expire after 24 hours, so for per-agent identity that renews itself, use the HTTP transport.

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
> Use gatehouse to get the OpenAI API key from api-keys/example
> Lease the GitHub token from git/github-pat for 10 minutes
> List all available secrets under api-keys/
```

---

## 2. OpenAI Codex CLI

Codex supports MCP servers via `~/.codex/config.toml`.

### Option A: stdio transport

```toml
[mcp_servers.gatehouse]
command = "bun"
args = ["run", "/path/to/gatehouse/src/mcp-stdio.ts"]

[mcp_servers.gatehouse.env]
GATEHOUSE_DATA_DIR = "/path/to/data"
GATEHOUSE_CONFIG_DIR = "/path/to/config"
GATEHOUSE_POLICIES = "agent-readonly"
# Add GATEHOUSE_MASTER_KEY = "..." only if /path/to/data has no master.key.
```

`command` is a string, `args` an array, and `env` a table. To forward a variable from your shell instead of writing its value here, list its name in `env_vars = ["GATEHOUSE_MASTER_KEY"]`.

### Option B: HTTP transport

```toml
[mcp_servers.gatehouse]
url = "http://gatehouse.local:3100/v1/mcp"
bearer_token_env_var = "GATEHOUSE_TOKEN"
```

Codex sends the value of `GATEHOUSE_TOKEN` from its environment as `Authorization: Bearer`.

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
Gatehouse exposes 11 tools - well under Windsurf's 100-tool limit.

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

Or use stdio. The Docker form works on a default install:
```json
{
  "mcpServers": {
    "gatehouse": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "-v", "gatehouse-data:/data", "ghcr.io/bshandley/gatehouse:latest", "mcp"]
    }
  }
}
```

Or from a checkout (add `GATEHOUSE_MASTER_KEY` to `env` only if the data dir has no `master.key`):
```json
{
  "mcpServers": {
    "gatehouse": {
      "command": "bun",
      "args": ["run", "/path/to/gatehouse/src/mcp-stdio.ts"],
      "env": {
        "GATEHOUSE_DATA_DIR": "/path/to/data",
        "GATEHOUSE_POLICIES": "agent-readonly"
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

Add `GATEHOUSE_MASTER_KEY` to `env` only if the data dir has no `master.key`.
```json
{
  "mcp": {
    "servers": {
      "gatehouse": {
        "type": "local",
        "command": ["bun", "run", "/path/to/gatehouse/src/mcp-stdio.ts"],
        "env": {
          "GATEHOUSE_DATA_DIR": "/path/to/data",
          "GATEHOUSE_POLICIES": "agent-readonly"
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
          "id": "api-keys/example2"
        }
      },
      "openai": {
        "apiKey": {
          "source": "exec",
          "provider": "gatehouse",
          "id": "api-keys/example"
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
  http://gatehouse.local:3100/v1/secrets/api-keys/example/value)

export ANTHROPIC_API_KEY=$(curl -s \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Accept: text/plain" \
  http://gatehouse.local:3100/v1/secrets/api-keys/example2/value)
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
  http://gatehouse.local:3100/v1/secrets/api-keys/example/value)

# Lease a secret (auto-expires)
LEASE=$(curl -s -X POST \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ttl": 600}' \
  http://gatehouse.local:3100/v1/lease/api-keys/example)

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

The REST examples below use `$ADMIN_JWT`, the token of an admin user (sign in with `POST /v1/auth/login`, see [Authentication](https://gatehouse.to/docs/authentication/)). On a fresh install, create that admin from the web UI with the one-time bootstrap token from the container log first. The bootstrap token, or a `GATEHOUSE_ROOT_TOKEN` set in the environment, also works as the bearer value.

```bash
# Create an AppRole for OpenClaw (read-only API keys, can lease)
curl -X POST http://localhost:3100/v1/auth/approle \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "openclaw-prod",
    "policies": ["agent-readonly"]
  }'
# Returns: { "role_id": "role-xxx", "secret_id": "yyy" }
# Save the secret_id - it's shown only once.

# Create a separate AppRole for Codex (coding agent with broader access)
curl -X POST http://localhost:3100/v1/auth/approle \
  -H "Authorization: Bearer $ADMIN_JWT" \
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
> Use gatehouse_proxy to call the OpenAI chat completions API with api-keys/example
```

The tool supports three injection styles (template, header injection, and `auto_inject`, where a list of secret paths is injected using each secret's `metadata.header_name`). The first two:

**Template style** - `{{secret:path}}` placeholders in headers, URL, or body:
```json
{
  "method": "POST",
  "url": "https://api.openai.com/v1/chat/completions",
  "headers": {
    "Authorization": "Bearer {{secret:api-keys/example}}",
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
  "inject": {"Authorization": "api-keys/example"},
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
    "inject": {"Authorization": "api-keys/example"}
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
curl -X POST http://gatehouse.local:3100/v1/secrets/api-keys/example \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -d '{"value": "sk-...", "metadata": {"allowed_domains": "api.openai.com,openai.com"}}'
```

If an agent tries to proxy this secret to `evil.com`, Gatehouse blocks it with a 403.

Each entry is one of:

| Entry | Matches |
|---|---|
| `example.com` | that host and any subdomain, on any port |
| `*.example.com` | subdomains only |
| `example.com:8443` | as above, on that port only |
| `10.0.0.50:5230` | that IP on that port |
| `[fd00::1]:8080` | an IPv6 address with a port |
| `10.0.0.0/24` | any IP-literal host inside the range |

Separate entries with commas, spaces, or newlines. Gatehouse validates the
list when the secret is written and rejects an invalid entry with a 400 that
names it. The same applies to `allowed_path_prefixes` (each entry starts with
`/`) and `auto_approve_from_ip` (IP addresses or CIDR ranges).

---

## Dynamic secrets

For databases and other backends that support programmatic credential creation,
Gatehouse can create temporary credentials on demand - no static passwords needed.

### Setting up PostgreSQL dynamic secrets

1. **Configure the connection** (admin):

```bash
curl -X POST http://gatehouse.local:3100/v1/dynamic \
  -H "Authorization: Bearer $ADMIN_JWT" \
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
  -H "Authorization: Bearer $ADMIN_JWT" \
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
  -H "Authorization: Bearer $ADMIN_JWT" \
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
  -H "Authorization: Bearer $ADMIN_JWT" \
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
  -H "Authorization: Bearer $ADMIN_JWT" \
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
configs are re-wrapped. You supply the new key: exactly 64 hex characters,
anything else is a 400.

```bash
# Generate a new key
NEW_KEY=$(openssl rand -hex 32)

# Rotate
curl -X POST http://gatehouse.local:3100/v1/admin/rotate-key \
  -H "Authorization: Bearer $GATEHOUSE_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"new_master_key\": \"$NEW_KEY\"}"
```

What happens to the key depends on where the old one came from:

- **Key-file install** (`master.key` in the data dir, including a key generated
  on first boot): the new key is written to `master.key` for you, and the old
  one is kept as `master.key.pre-rotate-<timestamp>`. Nothing else to do, but
  escrow the new key.
- **Env install** (`GATEHOUSE_MASTER_KEY`): nothing is saved. Set
  `GATEHOUSE_MASTER_KEY` to the new key before the next restart, or the server
  boots with a key that no longer decrypts the data. The response carries a
  `warning` saying so.

The response is `{rotated, secrets_rewrapped, dynamic_configs_rewrapped,
key_persisted_to, previous_key_kept_as, message, warning}`. `key_persisted_to`
and `previous_key_kept_as` are `null` on an env install, and `warning` appears
only when the key was not saved. Exports taken before a rotation need the old
key, so take a fresh export. See [Backup & Recovery](https://gatehouse.to/docs/backup/#after-rotating-the-master-key).

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
