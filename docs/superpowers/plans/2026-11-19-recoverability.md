# Recoverability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A fresh install boots with no hand-set key, and one command each backs up, exports, restores, and verifies the vault.

**Architecture:** Master-key resolution moves out of `src/config.ts` into `src/backup/keyfile.ts` (env, then key file, then generate on a fresh data dir). Three small units under `src/backup/` (snapshot, bundle, verify) are driven by a new `src/cli.ts` dispatcher that returns exit codes and is testable in-process. A shell entrypoint routes `backup | export | import | verify | mcp` inside the existing image.

**Tech Stack:** Bun, `bun:sqlite` (`VACUUM INTO`), `tweetnacl` secretbox, `node:crypto` `scryptSync` and `hkdfSync`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-06-05-recoverability-design.md`

## Global Constraints

- No new runtime dependencies.
- `GATEHOUSE_MASTER_KEY`, when set, always wins and behaves exactly as today. An env key that is set but invalid is a hard error, never a fall-through to the key file.
- Never generate a key when `gatehouse.db` already exists in the data dir.
- The escrow banner and every other key-bearing line goes to **stderr**. `src/mcp-stdio.ts` shares `loadConfig()` and stdout is its protocol channel.
- Key file: `${GATEHOUSE_DATA_DIR}/master.key`, hex, mode `0600`.
- scrypt parameters: `N=2^17, r=8, p=1`, 32-byte key. Pass `maxmem` explicitly (default is too small for this N).
- Passphrases never arrive as a flag value. `--passphrase-env VAR` or a TTY prompt, else fail closed.
- Exit codes: `0` ok, `1` general failure (bad args, wrong passphrase, verify failed), `2` key mismatch, `3` live server.
- Import is a full replace, never a merge.
- No em dashes anywhere. Test fixtures use `api-keys/example` and `api-keys/example2` as secret paths.
- Show the `bun test` pass count in every task report.
- Ships as `0.22.0`.

## Review Focus

1. **Stale WAL sidecars at import.** A `gatehouse.db-wal` or `-shm` left beside the replaced db would be replayed into the restored file. Import must remove both. Pinned in Task 6.
2. **Sealed import while `GATEHOUSE_MASTER_KEY` is set to a different key.** Env wins at next boot, so the restored vault would be undecryptable. Import must exit `2` unless `--force`. Pinned in Task 5.
3. **Banner on stdout.** A first run of the stdio MCP entry against an empty data dir would corrupt the protocol stream. Pinned in Tasks 1 and 2.
4. **Hand-edited `master.key`.** Trailing newline or spaces must be accepted. Garbage or a short key must throw, never regenerate. Pinned in Task 1.
5. **Corrupt, truncated, or foreign bundle file.** Must produce a one-line `bad_format` error and exit `1`, never a stack trace or a partial write. Pinned in Tasks 3 and 5.

## File Structure

| File | Responsibility |
|---|---|
| `src/backup/keyfile.ts` (new) | Resolve the master key, write the key file, print the banner |
| `src/backup/snapshot.ts` (new) | `VACUUM INTO` snapshot, server heartbeat lock |
| `src/backup/bundle.ts` (new) | Seal and open the passphrase bundle |
| `src/backup/verify.ts` (new) | Prove the key decrypts the data |
| `src/cli.ts` (new) | argv dispatch for `backup`, `export`, `import`, `verify` |
| `docker-entrypoint.sh` (new) | Route subcommands inside the image |
| `src/secrets/engine.ts` | Add `keyFingerprint`, `SecretsEngine.verifyKey` |
| `src/dynamic/manager.ts` | Add `DynamicSecretsManager.verifyKey` |
| `src/config.ts` | Call `resolveMasterKey` instead of throwing |
| `src/index.ts` | Heartbeat start and stop, fingerprint helper, `GET /v1/admin/key-verify` |
| `src/ui/index.html` | Settings row: "Encryption key: matches data" |

---

### Task 1: Key fingerprint helper and first-boot key resolution

**Files:**
- Create: `src/backup/keyfile.ts`, `test/keyfile.test.ts`
- Modify: `src/secrets/engine.ts` (next to `deriveKey`), `src/config.ts:11-18`, `src/index.ts:341-350`

**Interfaces:**
- Produces:
  - `keyFingerprint(masterKey: Buffer): string` in `src/secrets/engine.ts`. 32 hex chars, HKDF-SHA256, salt `gatehouse-v1`, info `gatehouse-fingerprint`, 16 bytes. Must equal what `GET /v1/admin/key-fingerprint` returns today.
  - `resolveMasterKey(opts: { envKey: string | undefined; dataDir: string; allowGenerate?: boolean; log?: (line: string) => void }): { key: Buffer; source: "env" | "file" | "generated" | "generated-unpersisted" }`. `allowGenerate` defaults to `true`, `log` defaults to `console.error`.
  - `class MasterKeyError extends Error { code: "missing" | "invalid_env" | "invalid_file" }`
  - `KEY_FILE_NAME = "master.key"`

- [ ] **Step 1: Write the failing tests** in `test/keyfile.test.ts`, each against a fresh `mkdtempSync` dir:

```ts
const HEX_A = "a".repeat(64);
test("keyFingerprint matches the documented HKDF output", () => {
  const expected = Buffer.from(hkdfSync("sha256", Buffer.from(HEX_A, "hex"), "gatehouse-v1", "gatehouse-fingerprint", 16)).toString("hex");
  expect(keyFingerprint(Buffer.from(HEX_A, "hex"))).toBe(expected);
});
test("env key wins even when a key file exists", () => {
  writeFileSync(join(dir, "master.key"), "b".repeat(64));
  const r = resolveMasterKey({ envKey: HEX_A, dataDir: dir, log: () => {} });
  expect(r.source).toBe("env");
  expect(r.key.toString("hex")).toBe(HEX_A);
});
test("invalid env key throws invalid_env and does not fall through to the file", () => {
  writeFileSync(join(dir, "master.key"), "b".repeat(64));
  expect(() => resolveMasterKey({ envKey: "short", dataDir: dir })).toThrow(expect.objectContaining({ code: "invalid_env" }));
});
test("key file is read, surrounding whitespace tolerated", () => {
  writeFileSync(join(dir, "master.key"), "  " + "b".repeat(64) + "\n");
  expect(resolveMasterKey({ envKey: undefined, dataDir: dir }).source).toBe("file");
});
test("garbage key file throws invalid_file and is left untouched", () => {
  writeFileSync(join(dir, "master.key"), "not-hex");
  expect(() => resolveMasterKey({ envKey: undefined, dataDir: dir })).toThrow(expect.objectContaining({ code: "invalid_file" }));
  expect(readFileSync(join(dir, "master.key"), "utf8")).toBe("not-hex");
});
test("fresh dir generates, persists 0600, and logs the banner with the key", () => {
  const lines: string[] = [];
  const r = resolveMasterKey({ envKey: undefined, dataDir: dir, log: (l) => lines.push(l) });
  expect(r.source).toBe("generated");
  expect(statSync(join(dir, "master.key")).mode & 0o777).toBe(0o600);
  expect(readFileSync(join(dir, "master.key"), "utf8").trim()).toBe(r.key.toString("hex"));
  expect(lines.join("\n")).toContain("GATEHOUSE GENERATED A NEW MASTER KEY");
  expect(lines.join("\n")).toContain(r.key.toString("hex"));
});
test("second resolve on the same dir reuses the key and logs nothing", () => { /* source "file", same key, zero log lines */ });
test("db present but no key anywhere throws missing, writes nothing", () => {
  writeFileSync(join(dir, "gatehouse.db"), "");
  expect(() => resolveMasterKey({ envKey: undefined, dataDir: dir })).toThrow(expect.objectContaining({ code: "missing" }));
  expect(existsSync(join(dir, "master.key"))).toBe(false);
});
test("allowGenerate false on a fresh dir throws missing", () => { /* ... */ });
test("unwritable data dir returns generated-unpersisted and still logs the key", () => {
  chmodSync(dir, 0o500); // skip when process.getuid?.() === 0
  /* source "generated-unpersisted", log contains the key and a not-persisted warning */
});
test("data dir that does not exist yet is created", () => { /* dataDir = join(dir, "nested"), source "generated" */ });
```

- [ ] **Step 2: Run** `bun test test/keyfile.test.ts`. Expected: FAIL, module not found.

- [ ] **Step 3: Implement.** `keyFingerprint` in `src/secrets/engine.ts`. `resolveMasterKey` in `src/backup/keyfile.ts` following spec D1 order. A valid key is 64 or more hex chars after `trim()`. Generation uses `crypto.randomBytes(32)`, writes with `{ mode: 0o600 }`, then `chmodSync` (umask). Banner copy is verbatim from spec D1 with the real path substituted. The `generated-unpersisted` banner replaces the "Saved to" line with `NOT SAVED: ${dir} is not writable. Set GATEHOUSE_MASTER_KEY to this value or the vault is lost on restart.`

- [ ] **Step 4: Wire it.** `loadConfig()` in `src/config.ts` calls `resolveMasterKey({ envKey: process.env.GATEHOUSE_MASTER_KEY, dataDir })` (compute `dataDir` first) and adds `masterKeySource` to `GatehouseConfig`. Replace the inline `hkdfSync` in the `GET /v1/admin/key-fingerprint` route with `keyFingerprint(config.masterKey)` and drop the unused import.

- [ ] **Step 5: Run** `bun test`. Expected: all pass, including the existing 745.

- [ ] **Step 6: Commit** `feat(recoverability): first-boot master key generation with escrow banner`

---

### Task 2: Consistent snapshot and server heartbeat lock

**Files:**
- Create: `src/backup/snapshot.ts`, `test/snapshot.test.ts`, `test/firstBoot.test.ts`
- Modify: `src/index.ts` (after `initDB`, and both signal handlers)

**Interfaces:**
- Produces:
  - `snapshotTo(dbPath: string, outPath: string): void`. `VACUUM INTO`. Throws `Error("output file already exists: <path>")` before opening the db when `outPath` exists, and a clear error when the parent dir is not writable.
  - `tableRowCounts(dbPath: string): Record<string, number>` for every user table.
  - `LOCK_FILE_NAME = "gatehouse.lock"`
  - `startHeartbeat(dataDir: string, intervalMs = 10_000): () => void`. Writes the lock file (JSON `{ pid, started_at }`), touches its mtime every interval, returns a stop function that clears the timer and deletes the file.
  - `isServerLive(dataDir: string, now = Date.now(), staleMs = 30_000): boolean`. True when the lock file exists and its mtime is within `staleMs`.

Why a heartbeat and not a pid check: import usually runs in a second container on the same volume, where the server's pid is meaningless. A crashed server's lock goes stale by itself in 30 seconds.

- [ ] **Step 1: Write the failing tests** in `test/snapshot.test.ts`:

```ts
test("snapshot of a WAL db with uncheckpointed writes contains them, and has no sidecars", () => {
  const db = initDB(dir); const eng = new SecretsEngine(db, KEY);
  eng.put("api-keys/example", "v1"); // db left open, WAL active
  snapshotTo(join(dir, "gatehouse.db"), join(out, "snap.db"));
  const snap = new Database(join(out, "snap.db"), { readonly: true });
  expect(snap.query("SELECT COUNT(*) AS n FROM secrets").get()).toEqual({ n: 1 });
  expect(existsSync(join(out, "snap.db-wal"))).toBe(false);
});
test("refuses to overwrite an existing output file", () => { /* toThrow(/already exists/) and the file bytes are unchanged */ });
test("tableRowCounts reports every table", () => { /* counts.secrets === 1, "audit_log" in counts */ });
test("heartbeat creates the lock, isServerLive is true, stop removes it", () => { /* ... */ });
test("a lock older than staleMs is not live", () => {
  const stop = startHeartbeat(dir, 60_000);
  expect(isServerLive(dir, Date.now() + 31_000)).toBe(false);
  stop();
});
test("no lock file is not live", () => { expect(isServerLive(dir)).toBe(false); });
```

- [ ] **Step 2: Run** `bun test test/snapshot.test.ts`. Expected: FAIL.

- [ ] **Step 3: Implement** `src/backup/snapshot.ts`. `VACUUM INTO` takes the path as a bound parameter.

- [ ] **Step 4: Wire the heartbeat** in `src/index.ts`: `const stopHeartbeat = startHeartbeat(config.dataDir)` after `initDB`, and call `stopHeartbeat()` in the `SIGTERM` and `SIGINT` handlers before `db.close()`.

- [ ] **Step 5: Write the boot test** `test/firstBoot.test.ts`. It spawns the real server (`Bun.spawn(["bun", "run", "src/index.ts"])`) with a temp `GATEHOUSE_DATA_DIR`, temp `GATEHOUSE_CONFIG_DIR`, a free `GATEHOUSE_PORT`, and `GATEHOUSE_MASTER_KEY` removed from the env, then polls `/health`:

```ts
test("bare boot generates a key, serves /health, and holds the lock", async () => {
  // after /health returns 200:
  expect(existsSync(join(dir, "master.key"))).toBe(true);
  expect(isServerLive(dir)).toBe(true);
  expect(stderr).toContain("GATEHOUSE GENERATED A NEW MASTER KEY");
  expect(stdout).not.toContain(readFileSync(join(dir, "master.key"), "utf8").trim());
});
test("second boot on the same dir prints no banner and keeps the fingerprint", async () => { /* stderr lacks the banner, master.key bytes unchanged */ });
test("SIGTERM removes the lock", async () => { /* ... */ });
```

- [ ] **Step 6: Run** `bun test`. Expected: all pass.

- [ ] **Step 7: Commit** `feat(recoverability): VACUUM INTO snapshot and server heartbeat lock`

---

### Task 3: Passphrase-sealed bundle

**Files:**
- Create: `src/backup/bundle.ts`, `test/bundle.test.ts`

**Interfaces:**
- Produces:

```ts
export interface BundleHeader {
  format: 1;
  gatehouse_version: string;
  created_at: string;            // ISO, supplied by the caller
  key_fingerprint: string;       // keyFingerprint() of the vault's master key
  sealed: boolean;               // true when master_key is present
  master_key?: string;           // hex, only when sealed
  row_counts: Record<string, number>;
}
export function sealBundle(input: {
  db: Uint8Array; passphrase: string; masterKey: Buffer; includeKey: boolean;
  createdAt: string; rowCounts: Record<string, number>; scryptLogN?: number; // default 17
}): Uint8Array;
export function openBundle(bytes: Uint8Array, passphrase: string): { header: BundleHeader; db: Uint8Array; masterKey: Buffer | null };
export class BundleError extends Error { code: "bad_passphrase" | "bad_format" | "unsupported_version" }
```

- File layout, all in the clear except the box:

| Offset | Size | Content |
|---|---|---|
| 0 | 8 | ASCII `GHBUNDLE` |
| 8 | 1 | format version, `1` |
| 9 | 1 | scrypt `log2(N)` |
| 10 | 16 | scrypt salt |
| 26 | 24 | secretbox nonce |
| 50 | rest | `secretbox(payload)` |

  `payload = u32be(headerLength) || headerJSON(utf8) || dbBytes`. `r=8`, `p=1`.

- [ ] **Step 1: Write the failing tests** (all pass `scryptLogN: 10` to stay fast):

```ts
test("sealed round-trip returns db bytes, header, and the master key", () => { /* masterKey equals input, header.sealed true, header.key_fingerprint === keyFingerprint(KEY) */ });
test("default mode carries no key", () => { /* masterKey null, header.sealed false, "master_key" not in header */ });
test("wrong passphrase is bad_passphrase", () => { /* toThrow code bad_passphrase */ });
test("foreign file is bad_format", () => { expect(() => openBundle(new TextEncoder().encode("SQLite format 3\0" + "x".repeat(100)), "pw")).toThrow(expect.objectContaining({ code: "bad_format" })); });
test("truncated bundle is bad_format", () => { /* sealed.slice(0, 40) and sealed.slice(0, 60) */ });
test("flipped ciphertext byte is bad_passphrase, not a crash", () => { /* ... */ });
test("version byte 2 is unsupported_version", () => { /* ... */ });
test("log2(N) outside 10..20 in the file is bad_format", () => { /* guards against a hostile file demanding gigabytes */ });
test("two seals of the same input differ", () => { /* fresh salt and nonce */ });
test("production default writes log2(N) = 17", () => { /* one seal without scryptLogN, expect bytes[9] === 17 */ });
```

- [ ] **Step 2: Run** `bun test test/bundle.test.ts`. Expected: FAIL.

- [ ] **Step 3: Implement** with `scryptSync(passphrase, salt, 32, { N: 2 ** logN, r: 8, p: 1, maxmem: 256 * 2 ** logN * 8 })` and `nacl.secretbox`. A failed `secretbox.open` maps to `bad_passphrase`.

- [ ] **Step 4: Run** `bun test test/bundle.test.ts`. Expected: PASS.

- [ ] **Step 5: Commit** `feat(recoverability): passphrase-sealed export bundle`

---

### Task 4: Verify, API route, and Settings row

**Files:**
- Create: `src/backup/verify.ts`, `test/verify.test.ts`
- Modify: `src/secrets/engine.ts`, `src/dynamic/manager.ts`, `src/index.ts` (beside the fingerprint route), `src/ui/index.html` (Settings, directly under the root token badge rendered from `cfg.root_token_set` near line 6620. The UI does not show the key fingerprint today, so show it on the same row.)

**Interfaces:**
- Consumes: `keyFingerprint` (Task 1).
- Produces:
  - `SecretsEngine.verifyKey(): { tested: boolean; ok: boolean }`. Unwraps the DEK of one `secrets` row. `tested: false` when the table is empty.
  - `DynamicSecretsManager.verifyKey(): { tested: boolean; ok: boolean }`. Decrypts one `dynamic_secrets.config` row.
  - `verifyVault(db: Database, masterKey: Buffer): { fingerprint: string; tested: "secret" | "dynamic" | "none"; ok: boolean }`. Tries secrets first, dynamic only when there are no secrets. `ok` is true for `"none"`.
  - `GET /v1/admin/key-verify`, admin only, returns the `verifyVault` result. 403 shape matches the fingerprint route.

- [ ] **Step 1: Write the failing tests:**

```ts
test("good key verifies against a secret", () => { /* put api-keys/example; { tested: "secret", ok: true } */ });
test("wrong key fails", () => { /* put with KEY_A, verifyVault(db, KEY_B) => { tested: "secret", ok: false } */ });
test("no secrets falls back to a dynamic config", () => { /* tested: "dynamic" */ });
test("empty vault reports none and ok", () => { /* { tested: "none", ok: true } */ });
test("verify does not bump last_accessed_at or write audit rows", () => { /* compare before and after */ });
test("GET /v1/admin/key-verify is 403 without admin and 200 with", () => { /* follow the router test pattern in test/secrets.test.ts */ });
```

- [ ] **Step 2: Run** `bun test test/verify.test.ts`. Expected: FAIL.

- [ ] **Step 3: Implement** the two `verifyKey` methods, `verifyVault`, and the route.

- [ ] **Step 4: UI.** In Settings, render one line from `GET /v1/admin/key-verify`: `Encryption key: matches data` when `ok` and `tested !== "none"`, `Encryption key: loaded, no encrypted rows to test` for `"none"`, and an error-styled `Encryption key: DOES NOT MATCH DATA` when not `ok`. Reuse existing status classes. No new CSS file.

- [ ] **Step 5: Run** `bun test`. Expected: all pass.

- [ ] **Step 6: Commit** `feat(recoverability): key verification in API and Settings`

---

### Task 5: CLI dispatcher and image entrypoint

**Files:**
- Create: `src/cli.ts`, `docker-entrypoint.sh`, `test/cli.test.ts`
- Modify: `Dockerfile` (ENTRYPOINT and CMD), `package.json` (`"bin": { "gatehouse": "src/cli.ts" }`, script `"cli": "bun run src/cli.ts"`), `.dockerignore` if it excludes the new script

**Interfaces:**
- Consumes: everything from Tasks 1 to 4.
- Produces: `runCli(argv: string[], io: { env: Record<string, string | undefined>; out: (s: string) => void; err: (s: string) => void; isTTY: boolean; prompt?: (label: string) => Promise<string>; now?: () => Date }): Promise<number>`. The file ends with `if (import.meta.main) process.exit(await runCli(process.argv.slice(2), realIo))`.

Commands (data dir from `GATEHOUSE_DATA_DIR`, default `/data`):

| Command | Behavior |
|---|---|
| `backup --out FILE` | `snapshotTo`. Prints the reminder line from spec D4. Works against a live server. |
| `export --out FILE [--passphrase-env VAR] [--no-key]` | Snapshot to a temp file in the OS temp dir, `sealBundle`, write `FILE` with mode `0600`, delete the temp. **Sealed (key included) is the default**, `--no-key` opts out. Rejects a passphrase shorter than 12 characters. Refuses when `FILE` exists. |
| `import --in FILE [--passphrase-env VAR] [--force]` | See the ordered steps below. |
| `verify` | Prints fingerprint and result. Exit `1` when not `ok`. Uses `allowGenerate: false`. |
| anything else, or `--help` | Usage to stderr, exit `1` (`0` for `--help`). |

Import, in this order, with no write before step 5:

1. `isServerLive(dataDir)` true: exit `3`, message tells the user to stop the server.
2. Read the passphrase, `openBundle`. `BundleError`: one line, exit `1`.
3. Pick the target key. Sealed bundle: the bundled key. If `GATEHOUSE_MASTER_KEY` is set and its fingerprint differs from the bundle's, exit `2` ("GATEHOUSE_MASTER_KEY is set to a different key than this backup carries. Unset it, or set it to the backup's key.") unless `--force`. Unsealed bundle: `resolveMasterKey({ allowGenerate: false })`. Missing key or fingerprint mismatch: exit `2` with the spec D3 message unless `--force`.
4. If `gatehouse.db` exists, rename it to `gatehouse.db.pre-import-<YYYYMMDDTHHMMSSZ>` (from `io.now`). Never delete it.
5. Write the snapshot to `gatehouse.db.import-tmp`, `fsync`, delete `gatehouse.db-wal` and `gatehouse.db-shm` if present, rename the temp over `gatehouse.db`.
6. Sealed and no env key set: write `master.key` (`0600`).
7. Run `verifyVault` on the restored db with the target key. Print fingerprint, row counts, and the pre-import path if one was made. Exit `1` if verify fails and `--force` was not used.

`docker-entrypoint.sh` (POSIX `sh`, `exec` in every branch):

```sh
#!/bin/sh
case "${1:-}" in
  backup|export|import|verify) exec bun run src/cli.ts "$@" ;;
  mcp) shift; exec bun run src/mcp-stdio.ts "$@" ;;
  "") exec bun run src/index.ts ;;
  *) exec bun run "$@" ;;   # keeps `docker run IMAGE src/index.ts` working
esac
```

Dockerfile: `COPY --chown=gatehouse:gatehouse docker-entrypoint.sh /app/`, `ENTRYPOINT ["/app/docker-entrypoint.sh"]`, `CMD []`.

- [ ] **Step 1: Write the failing tests** in `test/cli.test.ts`, calling `runCli` in-process with a capturing `io` and `GATEHOUSE_BUNDLE_SCRYPT_LOGN=10` in `io.env` (a test-only override the CLI passes to `sealBundle`, valid range 10 to 20):

```ts
test("backup writes a readable snapshot and prints the key reminder", async () => { /* exit 0, out contains "back up your master key separately" */ });
test("export fails closed with no passphrase source and no TTY", async () => { /* exit 1, no file written */ });
test("export rejects a passphrase under 12 chars", async () => { /* exit 1 */ });
test("export refuses to overwrite", async () => { /* exit 1, original bytes intact */ });
test("export file is mode 0600", async () => { /* ... */ });
test("export never echoes the passphrase or the master key", async () => { /* scan captured out and err */ });
test("import refuses a live server with exit 3", async () => { /* startHeartbeat(dir) first */ });
test("import with a wrong passphrase exits 1 and leaves the data dir byte-identical", async () => { /* ... */ });
test("import of a non-bundle file exits 1 with a one-line error", async () => { /* err has no 'at ' stack frames */ });
test("unsealed import with a different key exits 2 and writes nothing", async () => { /* ... */ });
test("unsealed import with --force restores anyway", async () => { /* exit 0 */ });
test("sealed import with a conflicting GATEHOUSE_MASTER_KEY exits 2", async () => { /* Review Focus 2 */ });
test("sealed import with a matching GATEHOUSE_MASTER_KEY does not write master.key", async () => { /* ... */ });
test("import keeps the previous db as gatehouse.db.pre-import-<stamp>", async () => { /* ... */ });
test("verify exits 0 on a good key and 1 on a wrong one", async () => { /* ... */ });
test("verify on an empty data dir exits 1 and does not create master.key", async () => { /* ... */ });
test("unknown command prints usage and exits 1", async () => { /* ... */ });
```

- [ ] **Step 2: Run** `bun test test/cli.test.ts`. Expected: FAIL.

- [ ] **Step 3: Implement** `src/cli.ts`, the entrypoint script (`chmod +x`), the Dockerfile change, and the `package.json` entries.

- [ ] **Step 4: Run** `bun test`. Expected: all pass.

- [ ] **Step 5: Verify the image.** `docker build -t gatehouse:plan-a .` then each must behave as noted:
  - `docker run --rm gatehouse:plan-a verify` exits `1` with "no master key" (empty anonymous volume, generation disallowed).
  - `docker run --rm -d -p 3999:3100 -v gh-plan-a:/data gatehouse:plan-a` serves `/health`, and `docker logs` shows the banner.
  - `docker run --rm -v gh-plan-a:/data gatehouse:plan-a verify` exits `0`.
  - `docker run --rm gatehouse:plan-a src/index.ts` still boots (back-compat branch).
  Remove the container and the `gh-plan-a` volume afterwards.

- [ ] **Step 6: Commit** `feat(recoverability): gatehouse backup, export, import, verify`

---

### Task 6: The restore drill

**Files:**
- Create: `test/backup.drill.test.ts`

**Interfaces:**
- Consumes: `runCli` (Task 5), `SecretsEngine`, `initDB`.

- [ ] **Step 1: Write the drill:**

```ts
test("sealed drill: export, lose everything, import, read back", async () => {
  // 1. resolveMasterKey on a fresh dir (generated), put 5 secrets api-keys/example-0..4 with distinct values,
  //    and one dynamic config. Close the db.
  // 2. runCli(["export", "--out", bundle, "--passphrase-env", "PW"]) => 0
  // 3. rmSync the whole data dir, recreate it empty.
  // 4. runCli(["import", "--in", bundle, "--passphrase-env", "PW"]) => 0
  // 5. resolveMasterKey again => source "file", same fingerprint as step 1.
  // 6. All 5 values read back equal. The dynamic config decrypts.
});
test("unsealed drill: a different master key is refused, the right one restores", async () => {
  // export --no-key with KEY_A; import with GATEHOUSE_MASTER_KEY=KEY_B => 2, dir still empty;
  // import with KEY_A => 0, values equal.
});
test("stale WAL sidecars beside the replaced db are removed", async () => {
  // target dir holds an existing vault plus hand-written gatehouse.db-wal and gatehouse.db-shm garbage files;
  // after import both are gone, the restored values read back, and the old db exists as pre-import.
});
test("export from a db held open with uncheckpointed writes includes those writes", async () => { /* ... */ });
```

- [ ] **Step 2: Run** `bun test test/backup.drill.test.ts`. Expected: PASS. Any failure is a bug in Tasks 1 to 5. Fix it there, in a separate commit.

- [ ] **Step 3: Commit** `test(recoverability): end-to-end restore drill`

---

### Task 7: Docs and release 0.22.0

**Files:**
- Create: `site/src/content/docs/backup.mdx` (copy the frontmatter shape of `security.mdx`. The sidebar is driven by the `sidebar_order` and `sidebar_group` frontmatter fields validated in `site/src/content.config.ts`: same group as `security`, ordered right after it.)
- Modify: `README.md` (docs table row, one feature bullet), `.env.example` (`GATEHOUSE_MASTER_KEY` is now optional, explain the key file), `site/src/content/docs/getting-started.mdx` and `security.mdx` (key file tradeoff from spec D1), `docs/superpowers/specs/2026-06-05-recoverability-design.md` (`Status: shipped in 0.22.0`), `CHANGELOG.md`, `src/version.ts`, `package.json`

- [ ] **Step 1: Write the Backup and Recovery page.** Sections: what a backup is (db plus key), the four commands with one `docker run --rm -v gatehouse-data:/data ghcr.io/bshandley/gatehouse <cmd>` example each, a cron one-liner for `backup` with a dated filename, the Proxmox note (snapshot the volume, escrow the key separately), escrow guidance, the exit-code table, and the restore walkthrough (stop the container, import, start). State plainly that a sealed export is only as strong as its passphrase and that export holds the snapshot in memory.

- [ ] **Step 2: Build the site.** `bun run site:build`. Expected: build succeeds and `docs/docs/backup/` exists.

- [ ] **Step 3: Bump** `VERSION` to `0.22.0` in `src/version.ts` and `package.json`. Add the `0.22.0` CHANGELOG block (first-boot key generation, the four commands, key-verify route and Settings row, new entrypoint with `mcp` routing, heartbeat lock).

- [ ] **Step 4: Run** `bun test` and `grep -rn $'\u2014' docs/superpowers/plans/2026-11-19-recoverability.md site/src/content/docs/backup.mdx CHANGELOG.md`. Expected: all tests pass, grep prints nothing.

- [ ] **Step 5: Commit** `feat(0.22.0): recoverability: first-boot key, backup, export, import, verify`. Landing, tagging, and publishing follow the repo CLAUDE.md release procedure and need the maintainer's go-ahead, since a push to `origin` redeploys the live instance.
