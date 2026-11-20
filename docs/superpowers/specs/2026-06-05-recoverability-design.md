# Recoverability: master-key lifecycle, backup, restore

Date: 2026-06-05
Status: shipped in 0.22.0
Sub-project A of the ubiquity roadmap. Build first.

## Problem

Gatehouse asks people to make it the single source of truth for every
credential their agents touch, but the answer to "what happens when this host
dies, or I fat-finger the master key" is currently "you lose all of it,
silently." There is a careful key-rotation ceremony (`POST /v1/admin/rotate-key`)
but no first-class backup, no export, and no documented or tested restore.

Until the answer is "here is one command to back up and one to restore, and
here is how the key is escrowed," serious users keep their real secrets
elsewhere and put only toys in Gatehouse.

## What the vault actually is

Two things:

1. `GATEHOUSE_MASTER_KEY`: 64+ hex chars, an env var (`src/config.ts:12`).
2. One SQLite file at `${GATEHOUSE_DATA_DIR}/gatehouse.db` (default `/data`),
   WAL mode, 14 tables (`src/db/init.ts`).

Secrets are envelope-encrypted: a per-secret DEK (NaCl secretbox,
XSalsa20-Poly1305) encrypts the value, and a KEK derived from the master key
(`deriveKey(masterKey, "gatehouse-kek")`) wraps the DEK. Dynamic provider
configs and leased credentials are encrypted with a separate derived key
(`gatehouse-dynamic-config`). Everything else in the DB is plaintext: the
audit log, policies, settings, usernames, AppRole display names, secret paths
and metadata.

Two consequences drive this design:

- A backup is "the SQLite content plus the escrowed master key." A Proxmox or
  cron job already copies the file fine. The missing, scary half is the key
  and a tested restore.
- Because much of the DB is plaintext, an export that is meant to leave the
  host (offsite, cloud, a USB stick) needs its own confidentiality. A raw file
  copy leaks the audit log and structure even though the secret values stay
  encrypted.

## Goals

- First boot generates a master key when none is provided, persists it, and
  prints a loud escrow banner. No more crash-on-missing-key for fresh installs.
- `gatehouse export` produces one portable, passphrase-sealed file safe to
  store anywhere.
- `gatehouse import` restores from that file, loudly refusing a key mismatch.
- `gatehouse backup` produces a consistent raw snapshot safe to drop in cron
  or a Proxmox backup job.
- `gatehouse verify` proves the running master key can decrypt the data.
- A test actually round-trips: create secrets, export, wipe, restore, read
  back, and assert the key-mismatch path refuses.

## Non-goals

- External KMS, HSM, or Shamir secret-sharing. Note as future, do not build.
- Continuous replication or point-in-time recovery. Snapshot granularity only.
- Changing the envelope scheme or the rotate-key ceremony.

## Design decisions (vetoable at review)

### D1. First-boot key generation persists to a key file, env always wins

On startup, resolve the master key in this order:

1. If `GATEHOUSE_MASTER_KEY` is set and valid, use it. (Unchanged behavior.)
2. Else if `${GATEHOUSE_DATA_DIR}/master.key` exists, read it.
3. Else if the data dir has no existing `gatehouse.db` (fresh install),
   generate 32 random bytes, write them hex-encoded to
   `${GATEHOUSE_DATA_DIR}/master.key` with mode 0600, and print the escrow
   banner.
4. Else (db exists but no key anywhere): refuse to start with the current
   explicit error. This is the "you moved the db but lost the key" case and
   must stay loud, never auto-generate over existing encrypted data.

Rationale: this is what makes `docker run` with no config work (distribution
needs it) while keeping the env-var path as the stronger-posture option. The
key file lives in the same volume as the encrypted db, so anyone with the
volume has both. That is the standard homelab convenience tradeoff and it is
made explicit in the banner. Operators who want at-rest separation set
`GATEHOUSE_MASTER_KEY` and delete `master.key`.

The escrow banner (printed once, on the boot that generates the key):

```
============================================================
 GATEHOUSE GENERATED A NEW MASTER KEY
 Saved to: /data/master.key

 This key encrypts every secret in this vault.
 If you lose it, the data is unrecoverable ciphertext.

 BACK IT UP NOW, somewhere other than this host:
   <the 64-char hex key>

 Stronger posture: set GATEHOUSE_MASTER_KEY to this value
 in your environment and delete /data/master.key.
============================================================
```

### D2. Export is a passphrase-sealed bundle, sealed mode includes the key

`gatehouse export --out FILE [--passphrase-env VAR] [--sealed]`

The bundle is: a consistent snapshot of `gatehouse.db` (see D4), plus a header
manifest (format version, created-at passed in by caller, key fingerprint,
table row counts, sealed flag), all wrapped under a key derived from a
passphrase via scrypt (N=2^17, r=8, p=1) and sealed with NaCl secretbox.

Two modes:

- Default: bundle does NOT contain the master key. Restoring it still needs
  the master key supplied separately. Use when the passphrase might be weak or
  the key is escrowed elsewhere.
- `--sealed`: bundle also contains the master key, so the passphrase is the
  single secret that recovers everything. This is the recommended homelab
  disaster-recovery mode: one file plus one passphrase in your password
  manager rebuilds the vault from nothing. The tradeoff is that passphrase
  strength is the whole game, stated in the help text.

The header always embeds the key fingerprint (the existing 16-byte
`gatehouse-fingerprint` HKDF output) so import can validate before touching
data, even in default mode.

Passphrase intake: `--passphrase-env` names an env var (never a flag value, to
keep it out of shell history and `ps`). Interactive prompt if absent and a TTY
is present. Fail closed if neither.

### D3. Import restores and refuses key mismatch loudly

`gatehouse import --in FILE [--passphrase-env VAR] [--force]`

Steps:

1. Derive the bundle key from the passphrase, open the secretbox. Wrong
   passphrase fails here with a clear message, no partial writes.
2. Read the header. Compare the bundle's key fingerprint against the
   fingerprint of the master key the target process would use (sealed bundles
   carry their own key, so they always match themselves).
3. If fingerprints differ and not `--sealed` and not `--force`: refuse with
   "this backup was made with a different master key. Set GATEHOUSE_MASTER_KEY
   to the matching key, or restore in sealed mode, or pass --force to restore
   the data anyway (secrets will be undecryptable)." This is the loud part.
4. Restore is atomic at the file level: write the snapshot to a temp path in
   the data dir, fsync, then rename over `gatehouse.db` only after the running
   server is stopped. Import refuses to run against a live server holding the
   db open (detect via a lock file or a running-pid check) to avoid corrupting
   WAL state.

Import never merges. It is a full replace. Merge semantics are out of scope.

### D4. Backup is VACUUM INTO, raw and consistent

`gatehouse backup --out FILE`

Uses SQLite `VACUUM INTO 'FILE'` to produce a single clean, consistent
snapshot even while WAL is active, without copying `-wal` and `-shm` sidecars.
This is the cron and Proxmox path. The output is ciphertext-at-rest for
secrets but plaintext for everything else, and it is useless without the
master key, so the command prints a one-line reminder: "remember to back up
your master key separately (or use `gatehouse export --sealed` for a
self-contained backup)."

Documented cron one-liner and a "just snapshot the whole /data volume plus
your key" note for the Proxmox crowd go in the docs, not the code.

### D5. Verify proves the key matches the data

`gatehouse verify`

Loads the resolved master key, derives the KEK and fingerprint, and:

- Prints the key fingerprint.
- Reads one secret row (if any exist) and confirms its DEK unwraps. If zero
  secrets, confirms the dynamic-config key path instead, else reports "no
  encrypted rows to test, key loaded."
- Exits non-zero on any unwrap failure.

This is the cheap, high-trust green check. The web UI surfaces the same result
as "Encryption key: matches data" in Settings (a small addition, owned here
but rendered in the UI).

## CLI surface and where it hangs

There is no CLI dispatcher today. The server is `bun run src/index.ts`; MCP
stdio is a separate entry file (`src/mcp-stdio.ts`), run directly; the site tooling
(`site/scripts/sync-docs.ts`, `site/scripts/publish.ts`) and
`scripts/screenshots.ts` are standalone scripts. There is no migration script:
`src/db/init.ts` creates and upgrades the schema at startup. Precedent is
standalone scripts run via bun.

Add `src/cli.ts` as a subcommand dispatcher: `backup`, `import`, `export`,
`verify`. Wire `package.json` scripts and a thin `gatehouse` shim so both of
these work:

```
bun run src/cli.ts export --out vault.gatehouse --sealed --passphrase-env PW
docker run --rm -v gatehouse-data:/data gatehouse:latest export --out ...
```

The Docker entrypoint already routes `mcp`; extend it to route these
subcommands to `src/cli.ts` so backup/restore run in the same image with the
same env and volume mounts.

## Components

- `src/backup/snapshot.ts`: VACUUM INTO consistent snapshot, lock/pid check.
- `src/backup/bundle.ts`: seal and open the passphrase bundle (scrypt +
  secretbox), header manifest read/write, fingerprint embed/check.
- `src/backup/keyfile.ts`: first-boot key resolution (D1), escrow banner.
- `src/cli.ts`: argv dispatch for the four subcommands.
- `src/config.ts`: call into `keyfile.ts` for resolution instead of the
  current throw-only path.
- Docker entrypoint: route subcommands.

Each unit is independently testable: snapshot against a temp db, bundle
seal/open round-trip in memory, keyfile resolution against a temp dir with the
four ordering cases.

## Error handling

- Wrong passphrase: clear single-line error, exit 1, no writes.
- Key-mismatch import without `--force`: refuse, exit 2, explain remedies.
- Import against a live server: refuse, exit 3, tell the user to stop it.
- Backup with no write permission on `--out`: fail before opening the db.
- First boot cannot write `master.key` (read-only volume): fall back to
  printing the key and instructing the user to set the env var, then continue
  using the in-memory generated key for this process (do not crash, but warn
  loudly that the key is not persisted).

## Testing

- Bundle seal/open round-trip, default and sealed, wrong-passphrase rejection.
- Keyfile resolution: env-set, file-present, fresh-generate, db-without-key
  refusal.
- The end-to-end drill, in `test/`: put N secrets, `export --sealed`, delete
  the db and key, `import`, read the N secrets back, assert equality. Then a
  default-mode export, swap to a different master key, assert import refuses
  without `--force`.
- `verify` exits zero on a good key and non-zero after the master key is
  tampered.

Surface the test pass count in the summary when these run.

## Rollout

1. `keyfile.ts` plus `config.ts` wiring and the banner. Ship behind the
   existing behavior: env-set installs are unaffected.
2. `snapshot.ts`, `bundle.ts`, `cli.ts`, entrypoint routing.
3. The restore drill test.
4. Docs: a Backup and Recovery page with the four commands, the cron
   one-liner, the Proxmox note, and the escrow guidance. This page is the thing
   that lets people commit.

## Resolved questions (2026-11-19)

Plan: `docs/superpowers/plans/2026-11-19-recoverability.md`.

- `export` defaults to sealed. `--no-key` opts out, replacing the `--sealed`
  flag in D2. One file plus one passphrase is the homelab disaster-recovery
  story, so it is the default. To offset the weaker default, export rejects a
  passphrase shorter than 12 characters.
- The live-server check is a heartbeat lock, not a pid file. The server writes
  `${GATEHOUSE_DATA_DIR}/gatehouse.lock` and touches it every 10 seconds;
  import refuses when the lock is fresher than 30 seconds. A pid is
  meaningless from a second container on the same volume, which is how import
  normally runs, and a crashed server's lock goes stale without help.
- Import does not delete an existing database. It renames it to
  `gatehouse.db.pre-import-<timestamp>` first. Still a full replace, never a
  merge.
- A sealed import refuses (exit 2) when `GATEHOUSE_MASTER_KEY` is set to a
  different key than the bundle carries, because env wins at the next boot and
  the restored vault would be undecryptable.
- The escrow banner prints to stderr. The stdio MCP entry shares the key
  resolution path and stdout is its protocol channel.
- The Docker entrypoint does not route `mcp` today (`ENTRYPOINT ["bun",
  "run"]`). This work adds a real entrypoint script that routes `mcp` and the
  four subcommands.
