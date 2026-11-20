import { describe, expect, test } from "bun:test";
import { scrubStream, type ScrubStats } from "../src/proxy/streamScrub";
import { scrubResponseBody, secretRedactionValues } from "../src/security/ssrf";

const enc = new TextEncoder();
const MARK = enc.encode("[REDACTED]");
const SECRET = "sk-example-0123456789abcdef";
const SECRET2 = "tok-example2-ZYXWVUTSRQ";

// ---------------------------------------------------------------- helpers

function bytes(...parts: (string | Uint8Array | number[])[]): Uint8Array {
  const arrs = parts.map((p) =>
    typeof p === "string" ? enc.encode(p) : p instanceof Uint8Array ? p : Uint8Array.from(p),
  );
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function indexOf(hay: Uint8Array, needle: Uint8Array, from = 0): number {
  outer: for (let i = from; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

function contains(hay: Uint8Array, needle: Uint8Array): boolean {
  return indexOf(hay, needle) !== -1;
}

/** Seeded PRNG (mulberry32) so a failing case is reproducible from its seed. */
function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** A pull-based source that hands out the given chunks one per pull. */
function fromChunks(chunks: Uint8Array[]) {
  let i = 0;
  const state = { pulls: 0, cancelled: false };
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(c) {
        state.pulls++;
        if (i < chunks.length) c.enqueue(chunks[i++]);
        else c.close();
      },
      cancel() {
        state.cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  return { stream, state };
}

/** A source the test drives by hand. */
function controlled() {
  let ctrl!: ReadableStreamDefaultController<Uint8Array>;
  const state = { pulls: 0, cancelled: false };
  const stream = new ReadableStream<Uint8Array>(
    {
      start(c) {
        ctrl = c;
      },
      pull() {
        state.pulls++;
      },
      cancel() {
        state.cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  return {
    stream,
    state,
    push: (b: Uint8Array | string) => ctrl.enqueue(typeof b === "string" ? enc.encode(b) : b),
    close: () => ctrl.close(),
    error: (e: unknown) => ctrl.error(e),
  };
}

function harness(extra: Partial<{ maxBytes: number; idleMs: number; redactValues: string[] }> = {}) {
  const ends: ScrubStats[] = [];
  let aborts = 0;
  const opts = {
    redactValues: extra.redactValues ?? [SECRET],
    maxBytes: extra.maxBytes ?? 1 << 30,
    idleMs: extra.idleMs ?? 5000,
    onEnd: (s: ScrubStats) => ends.push(s),
    abortUpstream: () => {
      aborts++;
    },
  };
  return { opts, ends, aborts: () => aborts };
}

async function readAll(s: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const r = s.getReader();
  const parts: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await r.read();
    if (done) break;
    parts.push(value);
  }
  return bytes(...parts);
}

async function run(chunks: Uint8Array[], redactValues: string[]) {
  const h = harness({ redactValues });
  const out = await readAll(scrubStream(fromChunks(chunks).stream, h.opts));
  expect(h.ends.length).toBe(1);
  return { out, stats: h.ends[0] };
}

const tick = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Reference oracle: leftmost match, then longest value, never rescanning a
 * replacement. Returns the output plus the "raw runs" (maximal stretches of
 * upstream bytes copied through between replacements).
 *
 * With `cut`, the input is a stream that was cut short (byte cap, idle
 * timeout, upstream error, client abort): only positions below
 * `input.length - (maxLen - 1)` are decided, whatever the bytes are, and the
 * rest (`held` bytes, a fixed tail less whatever a match below the bound
 * consumed) is withheld. `rawStarts` lists every input position emitted as a
 * raw byte.
 */
function oracle(input: Uint8Array, values: string[], cut = false) {
  const vs = [...new Set(values.filter((v) => v.length >= 8))]
    .map((v) => enc.encode(v))
    .sort((a, b) => b.length - a.length);
  const maxLen = vs.length ? vs[0].length : 0;
  const bound = cut ? input.length - Math.max(0, maxLen - 1) : input.length;
  const parts: Uint8Array[] = [];
  const runs: Uint8Array[] = [];
  let count = 0;
  let runStart = 0;
  let i = 0;
  const rawStarts: number[] = [];
  while (i < bound) {
    const v = vs.find((v) => i + v.length <= input.length && eq(input.subarray(i, i + v.length), v));
    if (v) {
      runs.push(input.subarray(runStart, i));
      parts.push(input.subarray(runStart, i), MARK);
      count++;
      i += v.length;
      runStart = i;
    } else rawStarts.push(i++);
  }
  runs.push(input.subarray(runStart, i));
  parts.push(input.subarray(runStart, i));
  return { out: bytes(...parts), runs, count, encoded: vs, held: input.length - i, rawStarts, maxLen };
}

/** True when v can share bytes with an adjacent "[REDACTED]" in the output. */
function canOverlapMark(v: Uint8Array): boolean {
  if (contains(MARK, v) || contains(v, MARK)) return true;
  for (let k = 1; k < Math.min(v.length, MARK.length); k++) {
    if (eq(MARK.subarray(MARK.length - k), v.subarray(0, k))) return true;
    if (eq(MARK.subarray(0, k), v.subarray(v.length - k))) return true;
  }
  return false;
}

/**
 * The leak invariant. No value lies wholly inside upstream bytes copied
 * through. For values that cannot share bytes with the replacement text, that
 * is the same as the value being absent from the output, so assert that too.
 */
function assertNoLeak(out: Uint8Array, input: Uint8Array, values: string[]) {
  const o = oracle(input, values);
  for (const v of o.encoded) {
    for (const run of o.runs) expect(contains(run, v)).toBe(false);
    if (!canOverlapMark(v)) expect(contains(out, v)).toBe(false);
  }
}

function splitAt(input: Uint8Array, cuts: number[]): Uint8Array[] {
  const sorted = [...cuts].sort((a, b) => a - b);
  const out: Uint8Array[] = [];
  let prev = 0;
  for (const c of sorted) {
    out.push(input.slice(prev, c));
    prev = c;
  }
  out.push(input.slice(prev));
  return out;
}

/**
 * Everything a caller can observe about a run apart from the bytes
 * themselves: the length of every emitted chunk, the total, and the stats.
 */
interface Obs {
  lens: number[];
  total: number;
  dropped: number;
  end: string;
  redactions: number;
}

async function observe(chunks: Uint8Array[], values: string[], maxBytes = 1 << 30): Promise<Obs> {
  const h = harness({ maxBytes, redactValues: values });
  const reader = scrubStream(fromChunks(chunks).stream, h.opts).getReader();
  const lens: number[] = [];
  for (;;) {
    const r = await reader.read();
    if (r.done) break;
    lens.push(r.value.length);
  }
  expect(h.ends.length).toBe(1);
  const s = h.ends[0];
  return { lens, total: lens.reduce((a, b) => a + b, 0), dropped: s.droppedBytes, end: s.end, redactions: s.redactions };
}

const WAITING = Symbol("waiting");

/**
 * Read every chunk that is readable now, without more upstream input. Returns
 * the emitted lengths and the read left pending (null once the stream ended).
 */
async function drainNow(reader: ReadableStreamDefaultReader<Uint8Array>) {
  const lens: number[] = [];
  for (;;) {
    const p = reader.read();
    const r = await Promise.race([p, tick(5).then(() => WAITING)]);
    if (r === WAITING) return { lens, pending: p as Promise<ReadableStreamReadResult<Uint8Array>> | null };
    const rr = r as ReadableStreamReadResult<Uint8Array>;
    if (rr.done) return { lens, pending: null };
    lens.push(rr.value.length);
  }
}

/**
 * Two inputs of equal length that differ only in [start, end): `a` holds a
 * proper prefix of `value` there, `b` unrelated bytes. Neither holds a full
 * occurrence of any value (asserted).
 */
function niPair(value: string, k: number, values: string[], pre = ".".repeat(24), post = "!" + ".".repeat(23)) {
  const a = enc.encode(pre + value.slice(0, k) + post);
  const b = enc.encode(pre + "#".repeat(enc.encode(value.slice(0, k)).length) + post);
  expect(a.length).toBe(b.length);
  expect(oracle(a, values).count).toBe(0);
  expect(oracle(b, values).count).toBe(0);
  const start = enc.encode(pre).length;
  return { a, b, start, end: a.length - enc.encode(post).length };
}

// ---------------------------------------------------------------- basics

describe("scrubStream: content", () => {
  test("bytes with no secrets pass through byte-identical (random binary, invalid UTF-8)", async () => {
    const r = rng(1);
    const input = new Uint8Array(4096);
    for (let i = 0; i < input.length; i++) input[i] = Math.floor(r() * 256);
    // Make sure some invalid UTF-8 is definitely in there.
    input.set([0xff, 0xfe, 0xc3, 0x28, 0xe2, 0x82], 100);
    const chunks = splitAt(input, [1, 7, 500, 501, 2000, 4095]);
    const { out, stats } = await run(chunks, [SECRET, SECRET2]);
    expect(eq(out, input)).toBe(true);
    expect(stats).toEqual({ bytesIn: 4096, redactions: 0, end: "complete", droppedBytes: 0 });
  });

  test("no usable values: chunks pass through with nothing held back", async () => {
    const src = controlled();
    const h = harness({ redactValues: ["short", ""] });
    const reader = scrubStream(src.stream, h.opts).getReader();
    const p = reader.read();
    src.push("abc");
    const first = await p;
    expect(new TextDecoder().decode(first.value)).toBe("abc");
    src.close();
    expect((await reader.read()).done).toBe(true);
    expect(h.ends).toEqual([{ bytesIn: 3, redactions: 0, end: "complete", droppedBytes: 0 }]);
  });

  test("a secret inside one chunk", async () => {
    const { out, stats } = await run([enc.encode(`key=${SECRET};`)], [SECRET]);
    expect(new TextDecoder().decode(out)).toBe("key=[REDACTED];");
    expect(stats.redactions).toBe(1);
  });

  test("a secret split across two chunks at every split point", async () => {
    const input = enc.encode(`{"echo":"Bearer ${SECRET}"}`);
    const want = enc.encode(`{"echo":"Bearer [REDACTED]"}`);
    for (let cut = 0; cut <= input.length; cut++) {
      const { out, stats } = await run(splitAt(input, [cut]), [SECRET]);
      expect(eq(out, want)).toBe(true);
      expect(stats.redactions).toBe(1);
    }
  });

  test("a secret split across three chunks", async () => {
    const input = enc.encode(`xx${SECRET}yy`);
    const want = enc.encode("xx[REDACTED]yy");
    for (let a = 2; a < 2 + SECRET.length; a++) {
      for (let b = a + 1; b < 2 + SECRET.length; b++) {
        const { out } = await run(splitAt(input, [a, b]), [SECRET]);
        expect(eq(out, want)).toBe(true);
      }
    }
  });

  test("two different secrets, raw and base64 forms", async () => {
    const values = secretRedactionValues([SECRET, SECRET2]);
    const text = `a ${SECRET} b ${btoa(SECRET2)} c ${SECRET2} d ${btoa(SECRET)}`;
    const { out, stats } = await run(splitAt(enc.encode(text), [5, 40, 41, 90]), values);
    expect(new TextDecoder().decode(out)).toBe("a [REDACTED] b [REDACTED] c [REDACTED] d [REDACTED]");
    expect(stats.redactions).toBe(4);
  });

  test("a secret at the very end of the stream", async () => {
    const { out, stats } = await run([enc.encode("tail:"), enc.encode(SECRET)], [SECRET]);
    expect(new TextDecoder().decode(out)).toBe("tail:[REDACTED]");
    expect(stats.redactions).toBe(1);
  });

  test("a non-ASCII secret is matched as UTF-8 bytes", async () => {
    const v = "pässwörd-ünïcode-ключ";
    const input = enc.encode(`<${v}>`);
    for (let cut = 0; cut <= input.length; cut++) {
      const { out } = await run(splitAt(input, [cut]), [v]);
      expect(new TextDecoder().decode(out)).toBe("<[REDACTED]>");
    }
  });

  test("overlapping candidates: leftmost wins, then longest", async () => {
    // Overlapping occurrences of one value: the leftmost is replaced, the
    // overlapped one is consumed with it.
    const v = "abababab";
    let r = await run([enc.encode("abababababab")], [v]);
    expect(new TextDecoder().decode(r.out)).toBe("[REDACTED]abab");
    expect(r.stats.redactions).toBe(1);

    // One value is a prefix of another: the longer one wins at the same start.
    r = await run([enc.encode("xx12345678ABCDyy")], ["12345678", "12345678ABCD"]);
    expect(new TextDecoder().decode(r.out)).toBe("xx[REDACTED]yy");
    expect(r.stats.redactions).toBe(1);

    // A shorter value starting earlier beats a longer value starting later.
    r = await run([enc.encode("QQQQQQQQRRRRRRRRRRRR")], ["QQQQQQQQRR", "QQQQRRRRRRRRRRRR"]);
    expect(new TextDecoder().decode(r.out)).toBe("[REDACTED]RRRRRRRRRR");
  });

  test("redaction count, and agreement with scrubResponseBody for one value", async () => {
    const text = `${SECRET}${SECRET}-${SECRET} x ${SECRET}`;
    const { out, stats } = await run(splitAt(enc.encode(text), [3, 30, 31]), [SECRET]);
    const buffered = scrubResponseBody(text, [SECRET]);
    expect(new TextDecoder().decode(out)).toBe(buffered.body);
    expect(stats.redactions).toBe(4);
    expect(stats.redactions).toBe(buffered.count);
  });

  test("values shorter than 8 characters are skipped, duplicates count once", async () => {
    const { out, stats } = await run([enc.encode("1234567 12345678")], ["1234567", "12345678", "12345678"]);
    expect(new TextDecoder().decode(out)).toBe("1234567 [REDACTED]");
    expect(stats.redactions).toBe(1);
  });

  test("a null source yields an empty stream that ends complete", async () => {
    const h = harness();
    const out = await readAll(scrubStream(null, h.opts));
    expect(out.length).toBe(0);
    expect(h.ends).toEqual([{ bytesIn: 0, redactions: 0, end: "complete", droppedBytes: 0 }]);
    expect(h.aborts()).toBe(0);
  });
});

// ---------------------------------------------------------------- property

describe("scrubStream: split invariance (seeded property test)", () => {
  const ADVERSARIAL: { values: string[]; input: string }[] = [
    // A value's prefix repeated before it.
    { values: ["aaaaaaab"], input: "aaaaaaaaaaaaaab" },
    { values: ["aaaaaaab"], input: "aaaaaaabaaaaaaaaaaaaaaab" },
    // One value a prefix / suffix / substring of another.
    { values: ["12345678", "12345678ABCDEF"], input: "012345678ABCDEF12345678ABC12345678" },
    { values: ["ZZ12345678", "12345678"], input: "ZZ12345678 12345678 Z12345678ZZ12345678" },
    { values: ["xyzSECRETSxyz", "SECRETSx"], input: "SECRETSxyzSECRETSxyzzSECRETSx" },
    // A value immediately followed by itself, and overlapping occurrences.
    { values: ["kkkkkkkk"], input: "kkkkkkkkkkkkkkkkkkkkkkkkk" },
    { values: ["abcabcabc"], input: "abcabcabcabcabcabcabcab" },
    { values: ["abababab", "babababa"], input: "abababababababababab" },
    // A value that is a prefix of the replacement text, or shares bytes with it.
    { values: ["[REDACTED"], input: "[REDACTED [REDACTED] [REDACTE[REDACTED" },
    { values: ["[REDACTE", "TED]tail"], input: "[REDACTEDTED]tail[REDACTE" },
    { values: ["[REDACTED]"], input: "[REDACTED][REDACTED]x" },
    // Chunks ending on partial-prefix boundaries: every prefix length k of a
    // value, followed by a byte that breaks it (every single cut point in
    // check() then ends a chunk inside each false start).
    ...["sk-example-0123", "abcabcabcab"].map((v) => ({
      values: [v],
      input: Array.from({ length: v.length - 1 }, (_, k) => v.slice(0, k + 1) + "!").join("") + v,
    })),
    // A longer value still forming where a shorter value already matched at
    // the same start: the longer one may complete, or may not.
    { values: ["12345678", "12345678ABCDEFGH"], input: "12345678ABCD!12345678ABCDEFGH12345678ABCDEFG" },
    { values: ["12345678", "12345678ABCDEFGH"], input: "12345678ABCDEFG" },
    // Text dense with false-start prefixes of overlapping values.
    { values: ["sk-example-0123", "sk-ex-ample99"], input: "sk-sk-exsk-examsk-ex-amsk-example-012sk-ex-ample99sk-example-0123sk-e" },
  ];

  function randomCase(r: () => number) {
    const alphabet = [0x61, 0x62, 0x5b, 0x5d, 0x00, 0xff, 0xc3];
    const values: string[] = [];
    const nValues = Math.floor(r() * 4);
    for (let k = 0; k < nValues; k++) {
      const len = 8 + Math.floor(r() * 10);
      let s = "";
      for (let i = 0; i < len; i++) s += r() < 0.7 ? "ab"[Math.floor(r() * 2)] : "xyz["[Math.floor(r() * 4)];
      values.push(s);
    }
    // Sometimes derive a value from another (prefix, suffix, substring).
    if (values.length && r() < 0.5) {
      const base = values[0] + "qqqq";
      const a = Math.floor(r() * 4);
      values.push(base.slice(a, a + 8 + Math.floor(r() * (base.length - a - 7))));
    }
    const parts: Uint8Array[] = [];
    const nParts = Math.floor(r() * 12);
    for (let k = 0; k < nParts; k++) {
      if (values.length && r() < 0.4) {
        const v = values[Math.floor(r() * values.length)];
        // Sometimes a truncated or doubled value.
        const roll = r();
        const k = 1 + Math.floor(r() * (v.length - 1)); // a random proper prefix
        parts.push(enc.encode(roll < 0.2 ? v.slice(0, v.length - 1) : roll < 0.35 ? v + v : roll < 0.6 ? v.slice(0, k) : v));
      } else {
        const n = Math.floor(r() * 10);
        const b = new Uint8Array(n);
        for (let i = 0; i < n; i++) b[i] = r() < 0.5 ? alphabet[Math.floor(r() * alphabet.length)] : Math.floor(r() * 256);
        parts.push(b);
      }
    }
    return { values, input: bytes(...parts) };
  }

  async function check(input: Uint8Array, values: string[], r: () => number, label: string) {
    const base = await run([input], values);
    const want = oracle(input, values);
    expect({ label, ok: eq(base.out, want.out) }).toEqual({ label, ok: true });
    expect(base.stats.redactions).toBe(want.count);
    expect(base.stats.bytesIn).toBe(input.length);
    assertNoLeak(base.out, input, values);

    const splits: Uint8Array[][] = [];
    for (let c = 0; c <= input.length; c++) splits.push(splitAt(input, [c]));
    for (let k = 0; k < 6; k++) {
      const cuts: number[] = [];
      const n = Math.floor(r() * (input.length + 2));
      for (let j = 0; j < n; j++) cuts.push(Math.floor(r() * (input.length + 1)));
      splits.push(splitAt(input, cuts)); // repeated cuts give empty chunks
    }
    splits.push(Array.from(input, (b) => Uint8Array.of(b))); // one-byte chunks
    for (const chunks of splits) {
      const got = await run(chunks, values);
      const ok = eq(got.out, base.out) && got.stats.redactions === base.stats.redactions;
      expect({ label, cuts: chunks.map((c) => c.length).join(","), ok }).toEqual({
        label,
        cuts: chunks.map((c) => c.length).join(","),
        ok: true,
      });
    }

    // A random byte cap. The cut output must equal the cut oracle, and no
    // position emitted raw may start an occurrence of a value in the FULL
    // input (the bytes the cap kept from us): a straddling secret is never
    // emitted in part. This is the no-prefix-at-end invariant stated
    // precisely; data that merely resembles a value prefix and then diverges
    // is legitimately emitted.
    const cap = Math.floor(r() * (input.length + 1));
    const capped = cap < input.length;
    const cutWant = oracle(input.subarray(0, cap), values, capped);
    for (const p of cutWant.rawStarts) {
      for (const v of cutWant.encoded) {
        const hit = p + v.length <= input.length && eq(input.subarray(p, p + v.length), v);
        expect({ label, cap, p, hit }).toEqual({ label, cap, p, hit: false });
      }
    }
    const capSplits = [[input], Array.from(input, (b) => Uint8Array.of(b)), splitAt(input, [Math.floor(r() * (input.length + 1))])];
    for (const chunks of capSplits) {
      const h = harness({ maxBytes: cap, redactValues: values });
      const out = await readAll(scrubStream(fromChunks(chunks).stream, h.opts));
      const ok =
        eq(out, cutWant.out) &&
        h.ends.length === 1 &&
        h.ends[0].end === (capped ? "byte_cap" : "complete") &&
        h.ends[0].droppedBytes === cutWant.held &&
        h.ends[0].redactions === cutWant.count;
      expect({ label, cap, cuts: chunks.map((c) => c.length).join(","), ok }).toEqual({
        label,
        cap,
        cuts: chunks.map((c) => c.length).join(","),
        ok: true,
      });
    }
  }

  test("adversarial fixed cases", async () => {
    const r = rng(7);
    for (const [i, c] of ADVERSARIAL.entries()) {
      await check(enc.encode(c.input), c.values, r, `adversarial #${i}`);
    }
  });

  /**
   * Noninterference with a random region: `a` holds a random proper prefix of
   * a value there, `b` random bytes, the rest is shared random bytes. Pairs
   * where either input holds a full occurrence are skipped (redrawn).
   */
  async function checkNoninterference(values: string[], r: () => number, label: string) {
    const usable = values.filter((v) => v.length >= 8);
    if (!usable.length) return;
    const alphabet = [0x61, 0x62, 0x5b, 0x5d, 0x78, 0x79, 0x7a, 0x00, 0xff];
    const rand = (n: number) =>
      Uint8Array.from({ length: n }, () => (r() < 0.6 ? alphabet[Math.floor(r() * alphabet.length)] : Math.floor(r() * 256)));
    for (let attempt = 0; attempt < 20; attempt++) {
      const v = enc.encode(usable[Math.floor(r() * usable.length)]);
      const k = 1 + Math.floor(r() * (v.length - 1));
      const pre = rand(Math.floor(r() * 50));
      const post = rand(Math.floor(r() * 50));
      const a = bytes(pre, v.subarray(0, k), post);
      const b = bytes(pre, rand(k), post);
      if (oracle(a, values).count || oracle(b, values).count) continue;
      const start = pre.length;
      const end = start + k;
      const cuts: number[] = [];
      for (let j = Math.floor(r() * 6); j > 0; j--) cuts.push(Math.floor(r() * (a.length + 1)));
      const chunkings = [
        (x: Uint8Array) => [x],
        (x: Uint8Array) => splitAt(x, [end]),
        (x: Uint8Array) => splitAt(x, [start, end]),
        (x: Uint8Array) => splitAt(x, cuts),
        (x: Uint8Array) => Array.from(x, (c) => Uint8Array.of(c)),
      ];
      const caps = [1 << 30, end, end + 1, Math.floor(r() * (a.length + 1)), Math.floor(r() * (a.length + 1))];
      for (const cap of caps) {
        for (const [ci, chunking] of chunkings.entries()) {
          const oa = await observe(chunking(a), values, cap);
          const ob = await observe(chunking(b), values, cap);
          expect({ label, k, start, cap, ci, obs: oa }).toEqual({ label, k, start, cap, ci, obs: ob });
        }
      }
      return;
    }
  }

  test("seeded random cases", async () => {
    for (let seed = 1; seed <= 150; seed++) {
      const r = rng(seed);
      const c = randomCase(r);
      await check(c.input, c.values, r, `seed ${seed}`);
      await checkNoninterference(c.values, r, `seed ${seed}`);
    }
  });
});

// ---------------------------------------------------------------- noninterference

// The prefix oracle this pins: if what is emitted, or when, depended on
// whether the latest bytes are a prefix of a secret, a caller who can make an
// echo upstream reflect a guess learns the secret one character at a time.
// Two inputs that differ only in a region (a proper prefix of a value versus
// unrelated bytes, neither a full occurrence) must look the same to the
// caller: same chunk lengths, same total, same droppedBytes, same end.
describe("scrubStream: noninterference (emission never depends on a partial match)", () => {
  const VALUES = secretRedactionValues([SECRET]); // raw 27 bytes, base64 36
  const cases = VALUES.flatMap((v) => Array.from({ length: v.length - 1 }, (_, i) => ({ v, k: i + 1 })));

  test("every cap position, four chunkings, every prefix length", async () => {
    for (const { v, k } of cases) {
      const { a, b, start, end } = niPair(v, k, VALUES);
      const chunkings = [
        (x: Uint8Array) => [x],
        (x: Uint8Array) => Array.from(x, (c) => Uint8Array.of(c)),
        // The region ends exactly at a chunk boundary, the next chunk crosses the cap.
        (x: Uint8Array) => splitAt(x, [end]),
        (x: Uint8Array) => splitAt(x, [start, end]),
      ];
      for (let cap = 0; cap <= a.length; cap++) {
        for (const [ci, chunking] of chunkings.entries()) {
          const oa = await observe(chunking(a), VALUES, cap);
          const ob = await observe(chunking(b), VALUES, cap);
          expect({ k, v: v.length, cap, ci, obs: oa }).toEqual({ k, v: v.length, cap, ci, obs: ob });
        }
      }
    }
  });

  test("idle timeout while the region is the latest data", async () => {
    const one = async (x: Uint8Array, shape: number[]) => {
      const src = controlled();
      const h = harness({ idleMs: 20, redactValues: VALUES });
      const reader = scrubStream(src.stream, h.opts).getReader();
      for (const c of splitAt(x, shape)) src.push(c);
      const lens: number[] = [];
      for (;;) {
        const r = await reader.read();
        if (r.done) break;
        lens.push(r.value.length);
      }
      expect(h.ends.length).toBe(1);
      return { lens, dropped: h.ends[0].droppedBytes, end: h.ends[0].end, bytesIn: h.ends[0].bytesIn };
    };
    await Promise.all(
      cases.flatMap(({ v, k }) => {
        const { a, b, start, end } = niPair(v, k, VALUES);
        // The upstream goes silent right after the region.
        const xa = a.subarray(0, end);
        const xb = b.subarray(0, end);
        return [[], [start]].map(async (shape) => {
          const oa = await one(xa, shape);
          const ob = await one(xb, shape);
          expect(oa.end).toBe("idle_timeout");
          expect({ k, v: v.length, shape, obs: oa }).toEqual({ k, v: v.length, shape, obs: ob });
        });
      }),
    );
  });

  test("consumer cancel while the region is the latest data", async () => {
    const one = async (x: Uint8Array, shape: number[]) => {
      const src = controlled();
      const h = harness({ redactValues: VALUES });
      const reader = scrubStream(src.stream, h.opts).getReader();
      for (const c of splitAt(x, shape)) src.push(c);
      const { lens, pending } = await drainNow(reader);
      expect(pending).not.toBeNull();
      await reader.cancel();
      expect(h.ends.length).toBe(1);
      return { lens, dropped: h.ends[0].droppedBytes, end: h.ends[0].end };
    };
    await Promise.all(
      cases.flatMap(({ v, k }) => {
        const { a, b, start, end } = niPair(v, k, VALUES);
        return [[], [start]].map(async (shape) => {
          const oa = await one(a.subarray(0, end), shape);
          const ob = await one(b.subarray(0, end), shape);
          expect(oa.end).toBe("client_abort");
          expect({ k, v: v.length, shape, obs: oa }).toEqual({ k, v: v.length, shape, obs: ob });
        });
      }),
    );
  });

  test("no cut: what is readable before the next chunk arrives is the same", async () => {
    const one = async (x: Uint8Array, cuts: number[]) => {
      const src = controlled();
      const h = harness({ redactValues: VALUES });
      const reader = scrubStream(src.stream, h.opts).getReader();
      const steps: number[][] = [];
      for (const c of splitAt(x, cuts)) {
        src.push(c);
        steps.push((await drainNow(reader)).lens);
      }
      src.close();
      const last = await drainNow(reader);
      expect(last.pending).toBeNull();
      steps.push(last.lens);
      return { steps, stats: h.ends };
    };
    await Promise.all(
      cases.flatMap(({ v, k }) => {
        const { a, b, start, end } = niPair(v, k, VALUES);
        return [[end], [start, end], [start, end, end + 1]].map(async (cuts) => {
          const oa = await one(a, cuts);
          const ob = await one(b, cuts);
          expect(oa.stats[0].end).toBe("complete");
          expect({ k, v: v.length, cuts, obs: oa }).toEqual({ k, v: v.length, cuts, obs: ob });
        });
      }),
    );
  });
});

// ---------------------------------------------------------------- streaming

describe("scrubStream: incremental output and back-pressure", () => {
  // harness() redacts SECRET alone, so the fixed hold-back is SECRET.length - 1.
  const HOLD = SECRET.length - 1;
  const dec = (b: Uint8Array | undefined) => new TextDecoder().decode(b);

  test("first chunk is readable before the source produces the second (fixed tail held)", async () => {
    const src = controlled();
    const h = harness();
    const reader = scrubStream(src.stream, h.opts).getReader();
    const first = reader.read();
    const c1 = `data: {"a":1}\n\n${"x".repeat(100)}`;
    src.push(c1);
    const got = await first;
    expect(got.done).toBe(false);
    expect(dec(got.value)).toBe(c1.slice(0, c1.length - HOLD));
    src.push("data: 2\n\n");
    src.close();
    const rest: Uint8Array[] = [];
    for (;;) {
      const r = await reader.read();
      if (r.done) break;
      rest.push(r.value);
    }
    expect(dec(bytes(got.value!, ...rest))).toBe(`${c1}data: 2\n\n`);
    expect(h.ends[0]).toEqual({ bytesIn: c1.length + 9, redactions: 0, end: "complete", droppedBytes: 0 });
  });

  // Reads what the scrubber has emitted so far without waiting for more input.
  async function readNow(reader: ReadableStreamDefaultReader<Uint8Array>, p = reader.read()) {
    const r = await Promise.race([p, tick(30).then(() => "waiting" as const)]);
    return { r, p };
  }

  test("(a) an SSE event longer than the hold-back is emitted up to the fixed tail at once", async () => {
    const key = "sk-example-" + "0123456789".repeat(19) + "z"; // 200 chars, base64 268
    const values = secretRedactionValues([key]);
    const hold = btoa(key).length - 1;
    const ev1 = `data: ${JSON.stringify({ text: "token ".repeat(80) })}\n\n`;
    expect(ev1.length).toBeGreaterThan(hold);
    const src = controlled();
    const h = harness({ redactValues: values });
    const reader = scrubStream(src.stream, h.opts).getReader();
    const p1 = reader.read();
    src.push(ev1);
    expect(dec((await p1).value)).toBe(ev1.slice(0, ev1.length - hold));
    // Only the fixed tail is pending: the next read waits on the upstream.
    const { r, p } = await readNow(reader);
    expect(r).toBe("waiting");
    // 14 new bytes release exactly 14 held bytes.
    src.push("data: [DONE]\n\n");
    expect(dec((await p).value)).toBe(ev1.slice(ev1.length - hold, ev1.length - hold + 14));
    src.close();
    const tail = await reader.read();
    expect(dec(tail.value)).toBe(`${ev1}data: [DONE]\n\n`.slice(ev1.length - hold + 14));
    expect((await reader.read()).done).toBe(true);
    expect(h.ends[0]).toEqual({ bytesIn: ev1.length + 14, redactions: 0, end: "complete", droppedBytes: 0 });
  });

  test("(b) a trailing partial prefix is held exactly as long as any other tail, then released", async () => {
    const src = controlled();
    const h = harness();
    const reader = scrubStream(src.stream, h.opts).getReader();
    const p1 = reader.read();
    const c1 = `data: ${"y".repeat(40)} ${SECRET.slice(0, 7)}`;
    src.push(c1);
    expect(dec((await p1).value)).toBe(c1.slice(0, c1.length - HOLD));
    const { r, p } = await readNow(reader);
    expect(r).toBe("waiting"); // the fixed tail is held, prefix or not
    src.push("!\n\n");
    expect(dec((await p).value)).toBe(c1.slice(c1.length - HOLD, c1.length - HOLD + 3));
    src.close();
    expect(dec((await reader.read()).value)).toBe(`${c1}!\n\n`.slice(c1.length - HOLD + 3));
    expect((await reader.read()).done).toBe(true);
    expect(h.ends[0].redactions).toBe(0);
  });

  test("(c) a value split across chunks is not emitted until it fits, then is one redaction", async () => {
    const src = controlled();
    const h = harness();
    const reader = scrubStream(src.stream, h.opts).getReader();
    const p1 = reader.read();
    src.push(`key=${SECRET.slice(0, 12)}`); // 16 bytes, all inside the hold-back
    const { r, p } = await readNow(reader, p1);
    expect(r).toBe("waiting");
    src.push(`${SECRET.slice(12)};`);
    // The match starts below the bound, so it is replaced and emitted whole.
    expect(dec((await p).value)).toBe("key=[REDACTED]");
    src.close();
    expect(dec((await reader.read()).value)).toBe(";");
    expect((await reader.read()).done).toBe(true);
    expect(h.ends[0]).toEqual({ bytesIn: 4 + SECRET.length + 1, redactions: 1, end: "complete", droppedBytes: 0 });
  });

  test("(d) a partial prefix held at end of stream is emitted as is", async () => {
    const src = controlled();
    const h = harness();
    const reader = scrubStream(src.stream, h.opts).getReader();
    const p1 = reader.read();
    src.push(`end of the stream: ${SECRET.slice(0, SECRET.length - 1)}`);
    expect(dec((await p1).value)).toBe("end of the stream: ");
    const p2 = reader.read();
    src.close();
    expect(dec((await p2).value)).toBe(SECRET.slice(0, SECRET.length - 1));
    expect((await reader.read()).done).toBe(true);
    expect(h.ends[0]).toEqual({ bytesIn: 19 + SECRET.length - 1, redactions: 0, end: "complete", droppedBytes: 0 });
  });

  test("a shorter value matched in full is not decided until the longest value fits", async () => {
    // maxLen 16, so 15 bytes are held back.
    const values = ["12345678", "12345678ABCDEFGH"];
    let src = controlled();
    let h = harness({ redactValues: values });
    let reader = scrubStream(src.stream, h.opts).getReader();
    const { r, p } = await readNow(reader);
    src.push("a 12345678ABC"); // 13 bytes: nothing is decided yet
    expect(r).toBe("waiting");
    expect((await readNow(reader, p)).r).toBe("waiting");
    src.push("DEFGH b");
    expect(dec((await p).value)).toBe("a [REDACTED]");
    src.close();
    expect(dec((await reader.read()).value)).toBe(" b");
    expect((await reader.read()).done).toBe(true);
    expect(h.ends[0].redactions).toBe(1);

    // The longer value breaks: once position 2 is below the bound, the
    // shorter value is replaced there.
    src = controlled();
    h = harness({ redactValues: values });
    reader = scrubStream(src.stream, h.opts).getReader();
    const p1 = reader.read();
    src.push(`a 12345678ABC!${"z".repeat(10)}`); // 24 bytes, bound 9
    expect(dec((await p1).value)).toBe("a [REDACTED]");
    src.close();
    expect(dec((await reader.read()).value)).toBe(`ABC!${"z".repeat(10)}`);
    expect((await reader.read()).done).toBe(true);
    expect(h.ends[0].redactions).toBe(1);
  });

  test("5 MB rich in false-start prefixes scrubs without quadratic blow-up", async () => {
    const key = "sk-example-" + "0123456789".repeat(19) + "z"; // 200 chars, base64 268
    const values = secretRedactionValues([key, SECRET]);
    // False starts of the raw key, its base64 form, and SECRET, each broken
    // late, plus a real occurrence now and then.
    const b64 = btoa(key);
    const unit = enc.encode(
      `${key.slice(0, 150)}!${b64.slice(0, 200)}#${SECRET.slice(0, 20)}~${"sk-ex".repeat(20)}`,
    );
    const chunkSize = 16 * 1024;
    const total = 5 * 1024 * 1024;
    const chunks: Uint8Array[] = [];
    let made = 0;
    let real = 0;
    while (made < total) {
      const c = new Uint8Array(chunkSize);
      for (let o = 0; o < chunkSize; o += unit.length) c.set(unit.subarray(0, Math.min(unit.length, chunkSize - o)), o);
      if (chunks.length % 50 === 0) {
        c.set(enc.encode(key), 100);
        real++;
      }
      chunks.push(c);
      made += chunkSize;
    }
    const t0 = performance.now();
    const { out, stats } = await run(chunks, values);
    const ms = performance.now() - t0;
    expect(stats.bytesIn).toBe(made);
    expect(stats.redactions).toBe(real);
    expect(contains(out.subarray(0, 4096), enc.encode(key))).toBe(false);
    expect(ms).toBeLessThan(10_000);
  });

  test("a consumer that never reads does not drain the source", async () => {
    let produced = 0;
    const src = new ReadableStream<Uint8Array>(
      {
        pull(c) {
          produced++;
          c.enqueue(new Uint8Array(1024).fill(0x61));
        },
      },
      { highWaterMark: 0 },
    );
    const h = harness();
    const out = scrubStream(src, h.opts);
    await tick(30);
    expect(produced).toBeLessThanOrEqual(1);

    const reader = out.getReader();
    await reader.read();
    await tick(30);
    expect(produced).toBeLessThanOrEqual(3);
    await reader.cancel();
    expect(h.ends.map((e) => e.end)).toEqual(["client_abort"]);
  });
});

// ---------------------------------------------------------------- limits and lifecycle

describe("scrubStream: limits and lifecycle", () => {
  test("byte_cap cuts at the cap, emits what is decided under it, aborts upstream", async () => {
    const c1 = "0123456789".repeat(3);
    const c2 = "abcdefghij".repeat(3);
    const { stream, state } = fromChunks([enc.encode(c1), enc.encode(c2), enc.encode("never")]);
    const h = harness({ maxBytes: 45 });
    const out = await readAll(scrubStream(stream, h.opts));
    // 45 bytes under the cap, the last SECRET.length - 1 of them withheld.
    const hold = SECRET.length - 1;
    expect(new TextDecoder().decode(out)).toBe((c1 + c2).slice(0, 45 - hold));
    expect(h.ends).toEqual([{ bytesIn: 60, redactions: 0, end: "byte_cap", droppedBytes: hold }]);
    expect(h.aborts()).toBe(1);
    expect(state.cancelled).toBe(true);
  });

  test("a stream that ends exactly at the cap is complete", async () => {
    const h = harness({ maxBytes: 10 });
    const out = await readAll(scrubStream(fromChunks([enc.encode("0123456789")]).stream, h.opts));
    expect(out.length).toBe(10);
    expect(h.ends).toEqual([{ bytesIn: 10, redactions: 0, end: "complete", droppedBytes: 0 }]);
    expect(h.aborts()).toBe(0);
  });

  // The reviewer's attack: an echo upstream reflects the injected header, and
  // the caller pads the request so the cap lands inside the secret.
  const KEY50 = "sk-example-" + "0123456789".repeat(3) + "abcdefghi";
  const ECHO_VALUES = secretRedactionValues([KEY50]);

  /** True when `out` ends with a proper prefix (8 bytes or more) of a value. */
  function endsWithValuePrefix(out: Uint8Array, values: string[]): boolean {
    for (const s of values) {
      const v = enc.encode(s);
      for (let k = 8; k < v.length; k++) {
        if (k <= out.length && eq(out.subarray(out.length - k), v.subarray(0, k))) return true;
      }
    }
    return false;
  }

  async function capSweep(body: string, values: string[], secretAt: number, secretLen: number) {
    const input = enc.encode(body);
    const chunkings = [
      (x: Uint8Array) => [x],
      (x: Uint8Array) => Array.from(x, (b) => Uint8Array.of(b)),
      (x: Uint8Array) => splitAt(x, [secretAt + Math.floor(secretLen / 2)]),
    ];
    for (let cap = 0; cap <= input.length; cap++) {
      for (const [ci, chunking] of chunkings.entries()) {
        const h = harness({ maxBytes: cap, redactValues: values });
        const out = await readAll(scrubStream(fromChunks(chunking(input)).stream, h.opts));
        const label = { cap, ci };
        expect({ ...label, full: values.some((v) => contains(out, enc.encode(v))) }).toEqual({ ...label, full: false });
        expect({ ...label, prefixAtEnd: endsWithValuePrefix(out, values) }).toEqual({ ...label, prefixAtEnd: false });
        const capped = cap < input.length;
        const want = oracle(input.subarray(0, cap), values, capped);
        expect({ ...label, ok: eq(out, want.out) }).toEqual({ ...label, ok: true });
        expect(h.ends.length).toBe(1);
        expect(h.ends[0].end).toBe(capped ? "byte_cap" : "complete");
        expect(h.ends[0].droppedBytes).toBe(want.held);
      }
    }
  }

  test("byte cap at every offset never emits a secret prefix (echoed raw value)", async () => {
    const body = `{"headers":{"Authorization":"Bearer ${KEY50}"}}`;
    await capSweep(body, ECHO_VALUES, body.indexOf(KEY50), KEY50.length);
  });

  test("byte cap at every offset never emits a secret prefix (echoed base64 form)", async () => {
    const b64 = btoa(KEY50);
    const body = `{"headers":{"Authorization":"Basic ${b64}"}}`;
    await capSweep(body, ECHO_VALUES, body.indexOf(b64), b64.length);
  });

  test("the reviewer's repro: cap one byte before the end of the secret withholds the prefix", async () => {
    const body = `{"headers":{"Authorization":"Bearer ${KEY50}"}}`;
    const cap = body.indexOf(KEY50) + KEY50.length - 1;
    const h = harness({ maxBytes: cap, redactValues: ECHO_VALUES });
    const out = new TextDecoder().decode(await readAll(scrubStream(fromChunks([enc.encode(body)]).stream, h.opts)));
    // The fixed tail is maxLen - 1 (the base64 form, 68 bytes): it covers the
    // 49 secret bytes under the cap and the 18 before them.
    const hold = btoa(KEY50).length - 1;
    expect(out).toBe(body.slice(0, cap - hold));
    expect(out.length).toBeLessThan(body.indexOf(KEY50));
    expect(h.ends).toEqual([{ bytesIn: body.length, redactions: 0, end: "byte_cap", droppedBytes: hold }]);
  });

  test("idle_timeout withholds the fixed tail (prefix included) and reports droppedBytes", async () => {
    const src = controlled();
    const h = harness({ idleMs: 40 });
    const reader = scrubStream(src.stream, h.opts).getReader();
    const p = reader.read();
    const c1 = `hello, this line is longer than the hold-back ${SECRET.slice(0, 10)}`;
    src.push(c1);
    const hold = SECRET.length - 1;
    expect(new TextDecoder().decode((await p).value)).toBe(c1.slice(0, c1.length - hold));
    expect((await reader.read()).done).toBe(true);
    expect(h.ends).toEqual([{ bytesIn: c1.length, redactions: 0, end: "idle_timeout", droppedBytes: hold }]);
    expect(h.aborts()).toBe(1);
    expect(src.state.cancelled).toBe(true);
  });

  test("consumer cancel withholds the fixed tail (prefix included) and reports droppedBytes", async () => {
    const src = controlled();
    const h = harness();
    const reader = scrubStream(src.stream, h.opts).getReader();
    const p = reader.read();
    const c1 = `x ${"-".repeat(30)} ${SECRET.slice(0, 9)}`;
    src.push(c1);
    const hold = SECRET.length - 1;
    expect(new TextDecoder().decode((await p).value)).toBe(c1.slice(0, c1.length - hold));
    await reader.cancel();
    expect(h.ends).toEqual([{ bytesIn: c1.length, redactions: 0, end: "client_abort", droppedBytes: hold }]);
  });

  test("empty chunks forever end idle_timeout without blocking the process", async () => {
    let pulls = 0;
    const src = new ReadableStream<Uint8Array>(
      {
        pull(c) {
          pulls++;
          c.enqueue(new Uint8Array(0));
        },
      },
      { highWaterMark: 0 },
    );
    const h = harness({ idleMs: 30 });
    let ticked = false;
    setTimeout(() => (ticked = true), 5);
    const t0 = Date.now();
    const out = await readAll(scrubStream(src, h.opts));
    expect(out.length).toBe(0);
    expect(ticked).toBe(true); // the event loop kept running
    expect(Date.now() - t0).toBeLessThan(1000);
    expect(pulls).toBeGreaterThan(16);
    expect(h.ends).toEqual([{ bytesIn: 0, redactions: 0, end: "idle_timeout", droppedBytes: 0 }]);
  });

  test("slow empty chunks do not restart the idle timer", async () => {
    const src = new ReadableStream<Uint8Array>(
      {
        async pull(c) {
          await tick(5);
          c.enqueue(new Uint8Array(0));
        },
      },
      { highWaterMark: 0 },
    );
    const h = harness({ idleMs: 40 });
    const t0 = Date.now();
    await readAll(scrubStream(src, h.opts));
    expect(Date.now() - t0).toBeLessThan(500);
    expect(h.ends[0].end).toBe("idle_timeout");
  });

  test("a source producing for longer than idleMs in total survives", async () => {
    let n = 0;
    const src = new ReadableStream<Uint8Array>(
      {
        async pull(c) {
          await tick(15);
          if (n++ < 10) c.enqueue(enc.encode(`data: ${n}\n\n`));
          else c.close();
        },
      },
      { highWaterMark: 0 },
    );
    const h = harness({ idleMs: 60 });
    const t0 = Date.now();
    const out = await readAll(scrubStream(src, h.opts));
    expect(Date.now() - t0).toBeGreaterThan(120);
    expect(new TextDecoder().decode(out)).toContain("data: 10");
    expect(h.ends[0].end).toBe("complete");
  });

  test("the idle timer does not run while the consumer is not pulling", async () => {
    const { stream } = fromChunks([enc.encode("a".repeat(100)), enc.encode("b".repeat(100))]);
    const h = harness({ idleMs: 20 });
    const reader = scrubStream(stream, h.opts).getReader();
    await reader.read();
    await tick(80);
    for (;;) if ((await reader.read()).done) break;
    expect(h.ends.map((e) => e.end)).toEqual(["complete"]);
  });

  test("a source error ends upstream_error and errors the output", async () => {
    const src = controlled();
    const h = harness();
    const reader = scrubStream(src.stream, h.opts).getReader();
    const p = reader.read();
    src.push("x".repeat(100));
    expect((await p).value!.length).toBe(100 - (SECRET.length - 1));
    const p2 = reader.read();
    src.error(new Error("upstream reset"));
    await expect(p2).rejects.toThrow("upstream reset");
    expect(h.ends).toEqual([{ bytesIn: 100, redactions: 0, end: "upstream_error", droppedBytes: SECRET.length - 1 }]);
    expect(h.aborts()).toBe(0);
  });

  test("a throw inside the scrubber (non-byte chunk) fails closed: upstream_error, source released", async () => {
    let ctrl!: ReadableStreamDefaultController<unknown>;
    let cancelled = false;
    const src = new ReadableStream<unknown>(
      { start: (c) => void (ctrl = c), cancel: () => void (cancelled = true) },
      { highWaterMark: 0 },
    );
    const h = harness();
    const reader = scrubStream(src as ReadableStream<Uint8Array>, h.opts).getReader();
    const p = reader.read();
    ctrl.enqueue(`not bytes ${SECRET}`);
    await expect(p).rejects.toThrow();
    expect(h.ends).toEqual([{ bytesIn: 0, redactions: 0, end: "upstream_error", droppedBytes: 0 }]);
    expect(cancelled).toBe(true);
  });

  test("consumer cancel ends client_abort and aborts upstream", async () => {
    const src = controlled();
    const h = harness();
    const reader = scrubStream(src.stream, h.opts).getReader();
    const p = reader.read();
    src.push("y".repeat(100));
    await p;
    await reader.cancel("caller went away");
    expect(h.ends).toEqual([{ bytesIn: 100, redactions: 0, end: "client_abort", droppedBytes: SECRET.length - 1 }]);
    expect(h.aborts()).toBe(1);
    expect(src.state.cancelled).toBe(true);
  });

  test("consumer cancel while a read is pending clears the idle timer", async () => {
    const src = controlled();
    const h = harness({ idleMs: 30 });
    const reader = scrubStream(src.stream, h.opts).getReader();
    const p = reader.read();
    await tick(5);
    await reader.cancel();
    expect((await p).done).toBe(true);
    await tick(60); // past idleMs: the timer must not fire a second end
    expect(h.ends.map((e) => e.end)).toEqual(["client_abort"]);
    expect(h.aborts()).toBe(1);
    expect(src.state.cancelled).toBe(true);
  });

  test("onEnd fires exactly once even if onEnd or abortUpstream throws", async () => {
    let calls = 0;
    // 30 bytes under the cap, 26 of them held back: "0123" is emitted.
    const s = scrubStream(fromChunks([enc.encode("0123456789".repeat(4))]).stream, {
      redactValues: [SECRET],
      maxBytes: 30,
      idleMs: 1000,
      onEnd: () => {
        calls++;
        throw new Error(`audit write failed ${SECRET}`);
      },
      abortUpstream: () => {
        throw new Error("abort failed");
      },
    });
    const logged: string[] = [];
    const orig = console.error;
    console.error = (...args: unknown[]) => void logged.push(args.map(String).join(" "));
    let out: Uint8Array;
    try {
      out = await readAll(s);
    } finally {
      console.error = orig;
    }
    expect(new TextDecoder().decode(out)).toBe("0123");
    expect(calls).toBe(1);
    // One line, naming the failure, with no chunk data and no redact value.
    expect(logged.length).toBe(1);
    expect(logged[0]).toContain("onEnd");
    expect(logged[0]).not.toContain("0123");
    expect(logged[0]).not.toContain(SECRET);
    expect(logged[0]).not.toContain("audit write failed");
  });

  test("onEnd fires exactly once across every ending", async () => {
    // complete, byte_cap, client_abort, upstream_error, idle_timeout
    const counts: Record<string, number> = {};
    const mk = (ends: ScrubStats[]) => (s: ScrubStats) => {
      ends.push(s);
      counts[s.end] = (counts[s.end] ?? 0) + 1;
    };
    const ends: ScrubStats[] = [];
    const base = { redactValues: [SECRET], maxBytes: 1000, idleMs: 30, onEnd: mk(ends) };
    await readAll(scrubStream(fromChunks([enc.encode("a")]).stream, base));
    await readAll(scrubStream(fromChunks([enc.encode("a".repeat(2000))]).stream, base));
    const r = scrubStream(fromChunks([enc.encode("a".repeat(100))]).stream, base).getReader();
    await r.read();
    await r.cancel();
    await r.cancel().catch(() => {});
    const bad = new ReadableStream<Uint8Array>({ pull: (c) => c.error(new Error("boom")) }, { highWaterMark: 0 });
    await readAll(scrubStream(bad, base)).catch(() => {});
    await readAll(scrubStream(controlled().stream, base));
    await tick(50);
    expect(counts).toEqual({ complete: 1, byte_cap: 1, client_abort: 1, upstream_error: 1, idle_timeout: 1 });
    expect(ends.length).toBe(5);
  });

  test("rejects an unusable idleMs or maxBytes (fail closed)", () => {
    const h = harness();
    expect(() => scrubStream(null, { ...h.opts, idleMs: 0 })).toThrow();
    expect(() => scrubStream(null, { ...h.opts, idleMs: Number.POSITIVE_INFINITY })).toThrow();
    expect(() => scrubStream(null, { ...h.opts, maxBytes: Number.NaN })).toThrow();
    expect(() => scrubStream(null, { ...h.opts, maxBytes: -1 })).toThrow();
  });
});
