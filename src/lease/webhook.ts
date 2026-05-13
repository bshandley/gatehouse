import { createHmac } from "node:crypto";

export interface LeaseRequestPayload {
  lease_id: string;
  identity: string;
  secret_path: string;
  justification: string;
  ttl_seconds: number;
  request_expires_at: string;
  /** Base URL of this Gatehouse instance, used to build approve_url and ui_url. */
  server_base_url: string;
}

// Module-level flag so we warn at most once per process about a private webhook
// target. Without this, every lease request would re-spam the log.
let warnedPrivate = false;

/**
 * String-based private/loopback hostname check. v1 deliberately avoids DNS
 * resolution (no node:dns); operators who use private hostnames must opt in
 * via GATEHOUSE_PROXY_ALLOW_PRIVATE=true.
 */
function isPrivateHostname(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h === "127.0.0.1" || h === "0.0.0.0" || h === "::1") {
    return true;
  }
  if (h.startsWith("10.") || h.startsWith("192.168.")) {
    return true;
  }
  // 172.16.0.0/12 -> second octet 16..31 inclusive
  if (h.startsWith("172.")) {
    const parts = h.split(".");
    if (parts.length >= 2) {
      const second = Number(parts[1]);
      if (Number.isInteger(second) && second >= 16 && second <= 31) {
        return true;
      }
    }
  }
  return false;
}

function buildBody(payload: LeaseRequestPayload): string {
  const base = payload.server_base_url.replace(/\/+$/, "");
  return JSON.stringify({
    event: "lease_request_created",
    lease_id: payload.lease_id,
    identity: payload.identity,
    secret_path: payload.secret_path,
    justification: payload.justification,
    ttl_seconds: payload.ttl_seconds,
    request_expires_at: payload.request_expires_at,
    approve_url: `${base}/v1/lease/${payload.lease_id}/approve`,
    ui_url: `${base}/#leases`,
  });
}

/**
 * Send a lease_request_created webhook. No-op when the URL env var is unset.
 * Never throws. Never awaits delivery.
 */
export function sendLeaseRequestWebhook(
  payload: LeaseRequestPayload,
  onError: (err: unknown) => void = (err) => console.error("[webhook]", err),
): void {
  const url = process.env.GATEHOUSE_APPROVAL_WEBHOOK_URL;
  if (!url) return;

  let hostname: string;
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch (err) {
    onError(err);
    return;
  }

  if (
    isPrivateHostname(hostname) &&
    process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE !== "true"
  ) {
    if (!warnedPrivate) {
      warnedPrivate = true;
      console.warn(
        `[webhook] refusing to deliver to private host '${hostname}'; set GATEHOUSE_PROXY_ALLOW_PRIVATE=true to allow`,
      );
    }
    return;
  }

  const body = buildBody(payload);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "User-Agent": "gatehouse-webhook/1.0",
  };

  const secret = process.env.GATEHOUSE_APPROVAL_WEBHOOK_SECRET;
  if (secret) {
    const ts = Math.floor(Date.now() / 1000).toString();
    const sig = createHmac("sha256", secret).update(`${ts}.${body}`).digest("hex");
    headers["X-Gatehouse-Timestamp"] = ts;
    headers["X-Gatehouse-Signature"] = `sha256=${sig}`;
  }

  // Fire-and-forget: no await, no retry. Caller (lease creation) must never
  // block on webhook delivery. 5s hard cap via AbortSignal.timeout.
  fetch(url, {
    method: "POST",
    headers,
    body,
    signal: AbortSignal.timeout(5000),
  }).catch(onError);
}

/**
 * Called once at startup. If the URL is set and points to a private host
 * with GATEHOUSE_PROXY_ALLOW_PRIVATE != "true", log a one-time warning to
 * console.warn so the operator notices their webhook will never fire.
 */
export function warnIfWebhookPrivate(): void {
  const url = process.env.GATEHOUSE_APPROVAL_WEBHOOK_URL;
  if (!url) return;
  let hostname: string;
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    return;
  }
  if (
    isPrivateHostname(hostname) &&
    process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE !== "true" &&
    !warnedPrivate
  ) {
    warnedPrivate = true;
    console.warn(
      `[webhook] GATEHOUSE_APPROVAL_WEBHOOK_URL points to private host '${hostname}'; set GATEHOUSE_PROXY_ALLOW_PRIVATE=true or deliveries will be skipped`,
    );
  }
}

/** Test seam: reset the one-time-warned flag. */
export function _resetWebhookWarnedForTests(): void {
  warnedPrivate = false;
}
