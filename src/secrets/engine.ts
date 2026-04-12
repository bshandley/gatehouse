import { Database } from "bun:sqlite";
import nacl from "tweetnacl";
import { encodeBase64, decodeBase64 } from "tweetnacl-util";
import { hkdfSync } from "crypto";

export interface StoredSecret {
  path: string;
  metadata: Record<string, string>;
  version: number;
  created_at: string;
  updated_at: string;
}

/**
 * Derive a 32-byte key from a master key using HKDF-SHA256 with domain separation.
 * Each purpose (KEK, JWT, etc.) gets a unique derived key.
 */
export function deriveKey(masterKey: Buffer, purpose: string): Uint8Array {
  return new Uint8Array(
    hkdfSync("sha256", masterKey, "gatehouse-v1", purpose, 32)
  );
}

/**
 * Envelope encryption scheme:
 * 1. Each secret gets its own random DEK (data encryption key)
 * 2. The secret value is encrypted with the DEK using XSalsa20-Poly1305
 * 3. The DEK is encrypted with the KEK (key encryption key) derived from the master key
 * 4. Both ciphertexts + nonces are stored in SQLite
 *
 * To decrypt: unwrap the DEK with the KEK, then decrypt the value with the DEK.
 * If the master key rotates, only DEKs need re-wrapping — values stay untouched.
 */
export class SecretsEngine {
  private db: Database;
  private kek: Uint8Array; // 32-byte key encryption key

  constructor(db: Database, masterKey: Buffer) {
    this.db = db;
    this.kek = deriveKey(masterKey, "gatehouse-kek");
  }

  put(
    path: string,
    value: string,
    metadata: Record<string, string> = {}
  ): StoredSecret {
    // Generate a random DEK for this secret
    const dek = nacl.randomBytes(nacl.secretbox.keyLength);

    // Encrypt the value with the DEK
    const valueNonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const encryptedValue = nacl.secretbox(
      new TextEncoder().encode(value),
      valueNonce,
      dek
    );

    // Encrypt the DEK with the KEK
    const dekNonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const encryptedDek = nacl.secretbox(dek, dekNonce, this.kek);

    // Read version + write UPSERT inside a single transaction so two
    // concurrent put() calls can't both read version N and both write
    // version N+1, clobbering each other's DEK/metadata.
    const putTxn = this.db.transaction(() => {
      const existing = this.db
        .query("SELECT version FROM secrets WHERE path = ?")
        .get(path) as { version: number } | null;

      const version = existing ? existing.version + 1 : 1;

      this.db
        .query(
          `INSERT INTO secrets (path, encrypted_value, nonce, encrypted_dek, dek_nonce, metadata, version, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
         ON CONFLICT(path) DO UPDATE SET
           encrypted_value = excluded.encrypted_value,
           nonce = excluded.nonce,
           encrypted_dek = excluded.encrypted_dek,
           dek_nonce = excluded.dek_nonce,
           metadata = excluded.metadata,
           version = excluded.version,
           updated_at = excluded.updated_at`
        )
        .run(
          path,
          Buffer.from(encryptedValue),
          Buffer.from(valueNonce),
          Buffer.from(encryptedDek),
          Buffer.from(dekNonce),
          JSON.stringify(metadata),
          version
        );
    });
    putTxn();

    return this.getMeta(path)!;
  }

  get(path: string): string | null {
    const row = this.db
      .query(
        "SELECT encrypted_value, nonce, encrypted_dek, dek_nonce FROM secrets WHERE path = ?"
      )
      .get(path) as {
      encrypted_value: Buffer;
      nonce: Buffer;
      encrypted_dek: Buffer;
      dek_nonce: Buffer;
    } | null;

    if (!row) return null;

    // Decrypt the DEK
    const dek = nacl.secretbox.open(
      new Uint8Array(row.encrypted_dek),
      new Uint8Array(row.dek_nonce),
      this.kek
    );

    if (!dek) {
      // Never leak the path in an error — it's caller-provided and the
      // response lands in the audit log / HTTP error body.
      throw new Error("Failed to decrypt DEK");
    }

    // Decrypt the value
    const value = nacl.secretbox.open(
      new Uint8Array(row.encrypted_value),
      new Uint8Array(row.nonce),
      dek
    );

    if (!value) {
      throw new Error("Failed to decrypt secret value");
    }

    return new TextDecoder().decode(value);
  }

  getMeta(path: string): StoredSecret | null {
    const row = this.db
      .query(
        "SELECT path, metadata, version, created_at, updated_at FROM secrets WHERE path = ?"
      )
      .get(path) as any;

    if (!row) return null;

    return {
      path: row.path,
      metadata: JSON.parse(row.metadata),
      version: row.version,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  list(prefix: string = ""): StoredSecret[] {
    const rows = this.db
      .query(
        "SELECT path, metadata, version, created_at, updated_at FROM secrets WHERE path LIKE ? ORDER BY path"
      )
      .all(`${prefix}%`) as any[];

    return rows.map((r) => ({
      path: r.path,
      metadata: JSON.parse(r.metadata),
      version: r.version,
      created_at: r.created_at,
      updated_at: r.updated_at,
    }));
  }

  delete(path: string): boolean {
    // Lease cleanup + secret delete must be atomic: if we crash between
    // the two DELETEs, the lease table orphans would point at a vanished
    // secret. Wrap both in a single transaction.
    const deleteTxn = this.db.transaction(() => {
      this.db
        .query("DELETE FROM leases WHERE secret_path = ?")
        .run(path);
      return this.db
        .query("DELETE FROM secrets WHERE path = ?")
        .run(path);
    });
    const result = deleteTxn();
    return result.changes > 0;
  }

  exists(path: string): boolean {
    const row = this.db
      .query("SELECT 1 FROM secrets WHERE path = ?")
      .get(path);
    return row !== null;
  }

  /**
   * Rotate the KEK: re-wrap all DEKs with a new key derived from the new master key.
   * Secret values are NOT re-encrypted — only the DEK wrapping changes.
   * Returns the number of secrets re-wrapped.
   *
   * The entire rotation runs inside a SQLite transaction. If any row fails
   * to decrypt (or any UPDATE fails), the transaction rolls back and the
   * database stays fully wrapped under the old KEK. The in-memory KEK is
   * only swapped after the transaction commits, so a mid-rotation crash
   * leaves the server in a recoverable state.
   */
  rotateKEK(newMasterKey: Buffer): number {
    const newKek = deriveKey(newMasterKey, "gatehouse-kek");

    const rotate = this.db.transaction(() => {
      const rows = this.db
        .query("SELECT path, encrypted_dek, dek_nonce FROM secrets")
        .all() as { path: string; encrypted_dek: Buffer; dek_nonce: Buffer }[];

      let count = 0;
      for (const row of rows) {
        // Decrypt DEK with old KEK
        const dek = nacl.secretbox.open(
          new Uint8Array(row.encrypted_dek),
          new Uint8Array(row.dek_nonce),
          this.kek
        );

        if (!dek) {
          // Aborting the transaction rolls back everything wrapped so far.
          throw new Error("Failed to decrypt DEK during rotation");
        }

        // Re-encrypt DEK with new KEK
        const newDekNonce = nacl.randomBytes(nacl.secretbox.nonceLength);
        const newEncryptedDek = nacl.secretbox(dek, newDekNonce, newKek);

        this.db
          .query(
            "UPDATE secrets SET encrypted_dek = ?, dek_nonce = ?, updated_at = datetime('now') WHERE path = ?"
          )
          .run(Buffer.from(newEncryptedDek), Buffer.from(newDekNonce), row.path);

        count++;
      }
      return count;
    });

    const count = rotate();
    // Only flip the in-memory KEK after the transaction commits.
    this.kek = newKek;
    return count;
  }
}
