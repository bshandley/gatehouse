/**
 * Streaming byte-level response scrubber for the passthrough route (spec D6).
 *
 * The upstream body is forwarded as it arrives, with every redact value
 * replaced by `[REDACTED]`, even when a value is split across network chunks.
 * The rules match `scrubResponseBody`: values shorter than 8 characters are
 * skipped, the replacement is `[REDACTED]`, the count is occurrences replaced.
 *
 * Matching. Values are compared as UTF-8 bytes. The scanner walks the input
 * left to right and, at each position, replaces the LONGEST value that starts
 * there (tie-break: leftmost match, then longest value). Replaced bytes are
 * skipped, and replacement text is never rescanned, so a match cannot form
 * across a replacement and nothing is counted twice.
 *
 * Hold-back (fixed). maxLen is the longest value in bytes. After every chunk,
 * positions at or beyond `bytes scanned - (maxLen - 1)` are never emitted,
 * whatever they contain; they are carried, unscanned, in front of the next
 * chunk. Every position below that bound has all maxLen bytes after it in
 * view, so its decision is final and it is emitted now. A match that starts
 * below the bound is replaced and emitted whole; one that starts at or beyond
 * it stays in the carry. With no usable values nothing is held back. A chunk
 * longer than the hold-back therefore produces output before the next chunk
 * arrives, and every chunk lags by at most maxLen - 1 bytes.
 *
 * Why the hold-back must not depend on content. Holding back only a tail that
 * looks like the start of a value would make what is emitted, and when, tell
 * the caller whether their latest bytes are a prefix of the secret. Against an
 * upstream that echoes caller-controlled content, the caller sends a guess and
 * watches whether it is delayed (or dropped at a cut it arranged): a prefix
 * oracle that recovers the secret one character at a time. With a fixed
 * hold-back, emission depends only on byte counts and full matches.
 *
 * Endings. Only a normal end of stream (`complete`) decides the carry: the
 * value cannot continue, so the carry is scanned as final and flushed. On
 * every abnormal end (`byte_cap`, `idle_timeout`, `upstream_error`,
 * `client_abort`) the carry is DROPPED, never flushed, and reported as
 * `droppedBytes`: the stream was cut, and the carry may hold the start of a
 * real secret (a caller can pad a request so a cap lands one byte before the
 * end of an echoed secret). The chunk that crosses the cap is truncated to the
 * cap and scanned non-final. So a cut always withholds the last
 * min(maxLen - 1, bytes read under the cap) bytes, less whatever a match
 * below the bound consumed, regardless of what they are. On `byte_cap` and
 * `idle_timeout` the stream is closed, not errored: Bun.serve (checked on
 * 1.3.14) ends an errored response stream with the normal closing chunk, so
 * erroring would not reach the client and only logs the error to stderr.
 *
 * Why chunking cannot change the result: a position is decided only when its
 * decision (which value, if any, matches there) can no longer change as more
 * bytes arrive, so each decision equals the unsplit run's decision at that
 * position. Decisions happen in the same order with the same jumps, so output
 * and count are identical for every chunking, and a match is never emitted in
 * part. A timer flush would break this and let a split value through.
 *
 * Cost. Values are indexed by first byte, so a byte that starts no value costs
 * one table lookup, and a byte that does costs at most candidates x maxLen
 * comparisons (the same naive check the buffered scrubber's split does). The
 * carry is never scanned before it is carried, so each position is decided
 * once; the only extra work is copying the carry (at most maxLen - 1 bytes)
 * once per chunk, so total work stays linear in stream length. No failure
 * function: a handful of values does not need one.
 *
 * Lifecycle. Pull-based with highWaterMark 0: the upstream is read only when
 * the consumer asks, and this stream itself never buffers the body. Under
 * Bun.serve, though, the server pulls regardless of whether the client is
 * reading and buffers the output itself, so for a slow client the byte cap
 * (maxBytes) is what bounds memory, not this pull design. The idle timer
 * runs only while waiting on an upstream read. `onEnd` is called exactly
 * once; every exit path clears the timer and cancels or releases the source
 * reader.
 */

export type StreamEnd = "complete" | "byte_cap" | "idle_timeout" | "upstream_error" | "client_abort";
export interface ScrubStats {
  bytesIn: number;
  redactions: number;
  end: StreamEnd;
  /** Held-back bytes withheld because the stream was cut (0 on complete). */
  droppedBytes: number;
}

const REPLACEMENT = new TextEncoder().encode("[REDACTED]");
const IDLE = Symbol("idle");
/** Consecutive empty reads allowed before yielding to the event loop. */
const EMPTY_READS_BEFORE_YIELD = 16;

class ByteMatcher {
  readonly maxLen: number;
  /** Values grouped by first byte, longest first within each group. */
  private readonly byFirst: (Uint8Array[] | undefined)[] = new Array(256);

  constructor(values: string[]) {
    const enc = new TextEncoder();
    const uniq = [...new Set(values.filter((v) => typeof v === "string" && v.length >= 8))]
      .map((v) => enc.encode(v))
      .sort((a, b) => b.length - a.length);
    this.maxLen = uniq.length ? uniq[0].length : 0;
    for (const v of uniq) (this.byFirst[v[0]] ??= []).push(v);
  }

  /**
   * Scan `buf` (the unscanned carry plus new bytes) from the start. Non-final:
   * decide only positions below `buf.length - (maxLen - 1)`, whatever the
   * bytes are, and return the rest as `carry`. Final: decide every position.
   */
  scan(buf: Uint8Array, final: boolean): { out: Uint8Array; carry: Uint8Array; count: number } {
    const n = buf.length;
    // Below the bound every value fits in the visible bytes, so each decision
    // is final. The bound depends only on byte counts, never on content.
    const bound = final ? n : n - (this.maxLen - 1);
    const parts: Uint8Array[] = [];
    let count = 0;
    let runStart = 0;
    let i = 0;
    while (i < bound) {
      const cands = this.byFirst[buf[i]];
      let matched = 0;
      if (cands) {
        // Longest first, so the first full hit is the longest that matches.
        for (const v of cands) {
          if (i + v.length > n) continue; // only at end of stream: a prefix is not the value
          let j = 1;
          while (j < v.length && buf[i + j] === v[j]) j++;
          if (j === v.length) {
            matched = v.length;
            break;
          }
        }
      }
      if (matched) {
        if (i > runStart) parts.push(buf.subarray(runStart, i));
        parts.push(REPLACEMENT);
        count++;
        i += matched;
        runStart = i;
      } else {
        i++;
      }
    }
    if (i > runStart) parts.push(buf.subarray(runStart, i));
    return { out: concat(parts), carry: buf.slice(i), count };
  }
}

function concat(parts: Uint8Array[]): Uint8Array {
  if (parts.length === 1) return parts[0].slice();
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function scrubStream(
  source: ReadableStream<Uint8Array> | null,
  opts: {
    redactValues: string[];
    maxBytes: number;
    idleMs: number;
    onEnd: (stats: ScrubStats) => void; // called exactly once
    abortUpstream?: () => void; // called on byte_cap, idle_timeout, client_abort
  },
): ReadableStream<Uint8Array> {
  // Fail closed: a limit that cannot be applied is a programming error.
  if (!Number.isFinite(opts.idleMs) || opts.idleMs <= 0) {
    throw new TypeError("scrubStream: idleMs must be a finite positive number");
  }
  if (Number.isNaN(opts.maxBytes) || opts.maxBytes < 0) {
    throw new TypeError("scrubStream: maxBytes must be a non-negative number");
  }

  const matcher = new ByteMatcher(opts.redactValues);
  let bytesIn = 0;
  let redactions = 0;
  let carry: Uint8Array = new Uint8Array(0);
  let finished = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let idle: Promise<typeof IDLE> | undefined;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;

  const clearTimer = () => {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
    idle = undefined;
  };

  /**
   * Arm the idle timer if it is not running. It is cleared only by a non-empty
   * chunk or an ending, so idle is measured from the last non-empty chunk and
   * empty reads cannot extend it.
   */
  const armIdle = (): Promise<typeof IDLE> =>
    (idle ??= new Promise((resolve) => {
      timer = setTimeout(() => resolve(IDLE), opts.idleMs);
    }));

  /** Scrub new bytes (with the carry in front). Final flushes everything. */
  const process = (chunk: Uint8Array, final: boolean): Uint8Array => {
    if (matcher.maxLen === 0) return chunk.slice();
    let buf = chunk;
    if (carry.length) {
      buf = new Uint8Array(carry.length + chunk.length);
      buf.set(carry, 0);
      buf.set(chunk, carry.length);
    }
    const r = matcher.scan(buf, final);
    carry = r.carry;
    redactions += r.count;
    return r.out;
  };

  const finish = (end: StreamEnd, abort: boolean) => {
    if (finished) return;
    finished = true;
    clearTimer();
    // Abnormal ends never flush the carry (see Endings). On complete it has
    // already been flushed, so this is 0.
    const droppedBytes = carry.length;
    carry = new Uint8Array(0);
    if (abort && opts.abortUpstream) {
      try {
        opts.abortUpstream();
      } catch {
        // The stream is ending regardless; nothing useful to do with this.
      }
    }
    if (reader) {
      if (end === "complete") {
        try {
          reader.releaseLock();
        } catch {
          // Already released.
        }
      } else {
        reader.cancel().catch(() => {});
      }
    }
    try {
      opts.onEnd({ bytesIn, redactions, end, droppedBytes });
    } catch (err) {
      // onEnd failing (an audit write, say) must not break the response. Log
      // the error's name only: its message could carry anything.
      const name = err instanceof Error ? err.name : typeof err;
      console.error(`scrubStream: onEnd threw ${name} (end=${end})`);
    }
  };

  return new ReadableStream<Uint8Array>(
    {
      start(controller) {
        if (!source) {
          controller.close();
          finish("complete", false);
          return;
        }
        reader = source.getReader();
      },

      async pull(controller) {
        if (finished || !reader) return;
        let empties = 0;
        try {
          for (;;) {
            // The idle promise goes first so an expired timer wins even when a
            // read is already resolved.
            const r = await Promise.race([armIdle(), reader.read()]);
            if (finished) return; // consumer cancelled while we waited

            if (r === IDLE) {
              // Cut: the carry is dropped, not flushed.
              controller.close();
              finish("idle_timeout", true);
              return;
            }
            if (r.done) {
              clearTimer();
              const tail = process(new Uint8Array(0), true);
              if (tail.length) controller.enqueue(tail);
              controller.close();
              finish("complete", false);
              return;
            }

            const chunk: unknown = r.value;
            if (!(chunk instanceof Uint8Array)) {
              throw new TypeError("scrubStream: upstream produced a non-byte chunk");
            }
            if (chunk.length === 0) {
              // No re-arm. A source that yields empty chunks synchronously
              // would otherwise keep this loop on the microtask queue and
              // starve the idle timer, so yield to a macrotask now and then.
              if (++empties % EMPTY_READS_BEFORE_YIELD === 0) {
                await new Promise((resolve) => setTimeout(resolve, 0));
                if (finished) return;
              }
              continue;
            }
            empties = 0;
            clearTimer();

            const room = opts.maxBytes - bytesIn;
            bytesIn += chunk.length;
            if (chunk.length > room) {
              // Truncate to the cap and scan NON-final: the fixed tail stays
              // in the carry and is dropped, whatever it holds.
              const out = process(chunk.subarray(0, Math.max(0, room)), false);
              if (out.length) controller.enqueue(out);
              controller.close();
              finish("byte_cap", true);
              return;
            }

            const out = process(chunk, false);
            if (out.length) {
              controller.enqueue(out);
              return;
            }
            // Fewer than maxLen bytes are unscanned, all held back: read more.
          }
        } catch (err) {
          if (finished) return;
          finish("upstream_error", false);
          controller.error(err);
        }
      },

      cancel() {
        finish("client_abort", true);
      },
    },
    { highWaterMark: 0 },
  );
}
