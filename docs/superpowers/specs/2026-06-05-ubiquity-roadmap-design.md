# Ubiquity roadmap: decomposition and sequencing

Date: 2026-06-05
Status: design, umbrella doc
Scope: strategy. Each sub-project below has its own spec and its own
implementation cycle.

## Where this came from

An external review argued that what gates Gatehouse becoming ubiquitous is
not the clever learning layer but two unglamorous things: people trusting it
enough to make it their only vault, and people being able to find and stand
it up. The review proposed five moves. This roadmap accepts the diagnosis,
verifies every technical claim in it against the code, and cuts the work into
four shippable sub-projects plus one deferred one.

The maintainer's call: both trust and adoption are live blockers, sequence
recovery first because it is foundational and cheap.

## The spine: master-key lifecycle

The connecting insight the review did not name: the master key's lifecycle is
the single thread running through recovery, distribution, and the operator
golden path.

1. First boot generates a key (distribution needs this so `docker run` works).
2. The user must escrow that key (recovery is meaningless without it).
3. The user must be walked off the bootstrap root token (golden path).

Design the key lifecycle once and it serves all three. This is also why
recovery-first does not fight adoption: the recovery work starts at first
boot, which is the adoption path's front door.

Verified facts that anchor the spine:

- `GATEHOUSE_MASTER_KEY` is a 64+ hex env var read in `src/config.ts:12`. The
  app throws and exits if it is missing. There is no first-boot generation.
- HKDF-SHA256 (salt `gatehouse-v1`) derives four purpose keys from it:
  `gatehouse-jwt`, `gatehouse-kek`, `gatehouse-dynamic-config`,
  `gatehouse-fingerprint` (`src/secrets/engine.ts:18`, `src/config.ts:24`,
  `src/dynamic/manager.ts:81`, `src/index.ts` fingerprint route).
- A 16-byte key fingerprint is already exposed at `GET /v1/admin/key-fingerprint`.
  Recovery reuses this to validate "this backup matches this key."
- The whole vault is one SQLite file at `${GATEHOUSE_DATA_DIR}/gatehouse.db`
  (default `/data`), WAL mode, 14 tables (`src/db/init.ts`).

## Decomposition

### A. Master-key lifecycle and recoverability (first)

First-boot key generation with a loud escrow banner. Encrypted, passphrase-
sealed export/import. A drop-in consistent snapshot safe for cron and Proxmox.
A `verify` command that proves the running key matches the data. A loud,
tested restore path including the key-mismatch refusal.

Why first: it is foundational (distribution and golden path both lean on
first-boot key generation), it is cheap (envelope encryption already exists,
so backup is "snapshot plus escrowed key"), and it is the trust gate.

Spec: `2026-06-05-recoverability-design.md`.

### B. Distribution (second, depends on A)

First-boot key and root-token generation so a bare `docker run` or one-click
install works with zero hand-set secrets. Kill the
`GATEHOUSE_ROOT_TOKEN=gatehouse-root-changeme` default in the shipped compose.
Catalog presence: Unraid Community Apps, Umbrel, CasaOS, Coolify. A clean
compose with sane defaults. Explicit "single-instance by design" positioning.

Why second: you do not put a compose in front of strangers until the
first-boot key and escrow story from A is solid. Otherwise every new user's
first experience is either a crash (no key) or a silent unrecoverable data
loss (generated key they never saved).

Spec: `2026-06-05-distribution-design.md`.

### C. Operator golden path (third, overlaps B)

A guided first-run in the web UI that takes a human from fresh install to "my
Claude Code is calling through Gatehouse" in one flow, then walks them off the
root token. Orchestrates the existing endpoints (AppRole create, hand-authored
policy attach, onboard link) and closes the loop by detecting the agent's
token exchange live.

Why third: it builds on A's key and pairs with B's compose. It is the
activation-rate lever once people can find and stand up the tool.

Spec: `2026-06-05-operator-golden-path-design.md`.

### D. Posture and value view (cheap, slot in anytime)

The review's items 4 and 5 collapse into one piece: a surface that makes the
invisible value visible. A persisted counter of credentials kept out of agent
context (the scrubber runs but records nothing today), plus secret-hygiene
nudges (unused 90 days, over 18 months old) computed from data we mostly
already have. Highest retention-leverage per line of code.

Why flexible: it touches no security-critical path and depends on nothing in
A, B, or C. It can ship first as a quick visible win, or interleave.

Spec: `2026-06-05-posture-value-view-design.md`.

### E. MCP-on-demand / learning layer (deferred)

The review is right: this is moat-depth that deepens engagement for people who
already live here, not a growth lever. The pattern engine
(`src/patterns/engine.ts`, `proxy_patterns` table) is the clever part, and the
temptation is to pour effort into it before the base that makes people stay is
solid. Build it after A through D. No spec yet, by design.

## Positioning note (not a sub-project)

Gatehouse is single-instance by design. The rate limiter is in-memory
(`src/rateLimits/limiter.ts`) and the event bus is in-process
(`src/events/bus.ts`). That is correct for homelab and should not change. It
must be stated plainly in the distribution copy so nobody deploys it expecting
HA. One sentence in the README, the catalog descriptions, and the compose
comments. Owned by spec B.

## Sequencing summary

```
A (recovery)  ->  B (distribution)  ->  C (golden path)
                       \                /
                        D (posture) slots in anywhere
                                    E (learning) deferred
```

Recommended order: A, then B and C in parallel (C can start once A lands), D
whenever a quick win is wanted, E last.
