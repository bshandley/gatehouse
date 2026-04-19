/**
 * In-process event bus for server-sent events. Fanned out to SSE subscribers.
 *
 * Events are plain objects {type, ...}. Currently emitted:
 *   - type: "audit", record: {...audit row}
 *   - type: "heartbeat" (emitted by the SSE handler itself)
 *
 * The bus runs in the same process as the audit logger; cross-process fan-out
 * would need Redis pub/sub or similar, which is out of scope for single-container
 * homelab deploys.
 */

export type GatehouseEvent =
  | { type: "audit"; record: Record<string, unknown> }
  | { type: "heartbeat"; ts: number };

type Listener = (e: GatehouseEvent) => void;

export class EventBus {
  private listeners = new Set<Listener>();

  subscribe(fn: Listener): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  emit(e: GatehouseEvent) {
    for (const l of this.listeners) {
      try {
        l(e);
      } catch {
        // A broken subscriber must not take down the emitter.
      }
    }
  }

  size(): number {
    return this.listeners.size;
  }
}
