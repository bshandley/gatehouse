import { execSync, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { DynamicProvider, DynamicCredential } from "./provider";

/**
 * SSH Certificate Dynamic Secrets Provider
 *
 * Signs short-lived SSH user certificates using a CA private key.
 * The agent receives a signed cert + ephemeral keypair valid for the requested TTL.
 *
 * On revoke, the cert is simply expired (SSH certs have built-in validity windows).
 * No remote state to clean up - the cert becomes worthless after TTL.
 *
 * Required config:
 *   ca_private_key - PEM-encoded CA private key (the signing authority)
 *   principals     - Comma-separated allowed usernames (default: the agent identity)
 *                    e.g. "ubuntu,deploy" or "root"
 *   extensions     - Comma-separated cert extensions (default: "permit-pty")
 *                    e.g. "permit-pty,permit-port-forwarding,permit-agent-forwarding"
 *   allowed_hosts  - Comma-separated advisory list of hosts that accept this cert.
 *                    NOT enforced at cert-signing time (SSH certs aren't host-scoped),
 *                    but surfaced to agents in gatehouse_list and the checkout
 *                    response so they know where to connect. e.g. "10.0.0.107,db.lab"
 *
 * Server-side setup:
 *   1. Generate a CA keypair: ssh-keygen -t ed25519 -f gatehouse_ca -N ""
 *   2. Store the private key in Gatehouse config: ca_private_key = contents of gatehouse_ca
 *   3. On target hosts, add to /etc/ssh/sshd_config:
 *        TrustedUserCAKeys /etc/ssh/gatehouse_ca.pub
 *   4. Copy gatehouse_ca.pub to /etc/ssh/gatehouse_ca.pub on each target host
 */
export class SSHCertProvider implements DynamicProvider {
  readonly type = "ssh-cert";

  requiredConfig(): string[] {
    return ["ca_private_key"];
  }

  async create(
    config: Record<string, string>,
    identity: string,
    ttlSeconds: number
  ): Promise<DynamicCredential> {
    const workDir = mkdtempSync(join(tmpdir(), "gh-ssh-"));

    try {
      // Normalize CA key: strip \r (CRLF from browser paste), ensure trailing \n
      const caKeyPath = join(workDir, "ca_key");
      writeFileSync(caKeyPath, config.ca_private_key.replace(/\r/g, "").trim() + "\n", { mode: 0o600 });

      // Generate an ephemeral keypair for the agent
      const keyPath = join(workDir, "agent_key");
      execSync(
        `ssh-keygen -t ed25519 -f ${keyPath} -N "" -q`,
        { timeout: 10_000 }
      );

      const privateKey = readFileSync(keyPath, "utf-8");
      const publicKey = readFileSync(`${keyPath}.pub`, "utf-8").trim();

      // Determine principals
      const principals = config.principals || sanitize(identity);
      const extensions = (config.extensions || "permit-pty")
        .split(",")
        .map((e) => e.trim())
        .filter(Boolean);

      // Build ssh-keygen signing command using spawnSync to avoid shell injection
      const certId = `gh_${sanitize(identity)}_${crypto.randomUUID().slice(0, 8)}`;
      const args = [
        "-s", caKeyPath,
        "-I", certId,
        "-n", principals,
        "-V", `+${ttlSeconds}s`,
        ...extensions.flatMap((e) => ["-O", e]),
        `${keyPath}.pub`,
      ];

      const result = spawnSync("ssh-keygen", args, { timeout: 10_000 });
      if (result.status !== 0) {
        throw new Error(`ssh-keygen signing failed: ${result.stderr?.toString() || "unknown error"}`);
      }

      const certificate = readFileSync(`${keyPath}-cert.pub`, "utf-8").trim();

      // Extract CA public key for reference
      let caPublicKey = "";
      try {
        const caPubPath = join(workDir, "ca_key.pub");
        execSync(`ssh-keygen -y -f ${caKeyPath} > ${caPubPath}`, { timeout: 5_000 });
        caPublicKey = readFileSync(caPubPath, "utf-8").trim();
      } catch {
        // Non-critical
      }

      const allowedHosts = (config.allowed_hosts || "").trim();

      return {
        credential: {
          private_key: privateKey,
          public_key: publicKey,
          certificate,
          cert_id: certId,
          principals,
          valid_seconds: String(ttlSeconds),
          ca_public_key: caPublicKey,
          ...(allowedHosts ? { allowed_hosts: allowedHosts } : {}),
          usage: `Write private_key to <path> (mode 0600) and certificate to <path>-cert.pub (the same prefix with -cert.pub appended). Then: ssh -i <path> -o IdentitiesOnly=yes -o IdentityAgent=none <principal>@<host>. SSH auto-discovers the cert from the -cert.pub sibling. IdentitiesOnly + IdentityAgent=none prevent other keys in the local SSH agent from overriding the cert. Avoid -o CertificateFile=<path>: some OpenSSH builds error out with "Load key: error in libcrypto" if the cert file ordering is unusual; the sibling-file convention works everywhere.`,
        },
        revocation_handle: certId,
      };
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  }

  async revoke(
    _config: Record<string, string>,
    _revocationHandle: string
  ): Promise<void> {
    // SSH certs are self-expiring - no remote state to clean up.
    // The cert's validity window is baked in at signing time.
    // For extra security, a KRL (Key Revocation List) could be maintained,
    // but that's overkill for homelab use where TTLs are short.
  }

  async validate(
    config: Record<string, string>
  ): Promise<{ ok: boolean; error?: string }> {
    const workDir = mkdtempSync(join(tmpdir(), "gh-ssh-validate-"));

    try {
      // Check that ssh-keygen is available
      try {
        execSync("which ssh-keygen", { timeout: 5_000 });
      } catch {
        return { ok: false, error: "ssh-keygen not found in PATH - install openssh (e.g. apt install openssh-client / pacman -S openssh)" };
      }

      // Normalize the CA key: strip \r (CRLF from browser paste breaks libcrypto), ensure trailing \n
      const caKeyPath = join(workDir, "ca_key");
      let keyData = config.ca_private_key?.replace(/\r/g, "").trim();
      if (!keyData || !keyData.includes("PRIVATE KEY")) {
        return { ok: false, error: "CA private key is missing or does not contain a PEM key block" };
      }
      keyData += "\n";
      writeFileSync(caKeyPath, keyData, { mode: 0o600 });

      try {
        const result = execSync(`ssh-keygen -y -f ${caKeyPath}`, {
          timeout: 5_000,
          encoding: "utf-8",
          stdio: ["pipe", "pipe", "pipe"],
        });
        if (!result.startsWith("ssh-")) {
          return { ok: false, error: "CA private key does not appear to be a valid SSH key" };
        }
      } catch (err: any) {
        const detail = err.stderr?.toString().trim() || err.stdout?.toString().trim() || err.message;
        return { ok: false, error: `Invalid CA private key: ${detail}` };
      }

      return { ok: true };
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  }
}

function sanitize(s: string): string {
  return s.replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 20);
}
