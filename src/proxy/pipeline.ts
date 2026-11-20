/**
 * Shared proxy pipeline. Every surface that forwards a request with secrets
 * injected (REST /v1/proxy, the MCP gatehouse_proxy tool, passthrough) runs
 * its controls through here so there is exactly one copy of them:
 *
 *   authorizeProxyCall: policy, rate-limit and approval gates, secret
 *     resolution, allowed_domains, allowed_path_prefixes, private-network
 *     policy, protocol check. Writes the denial audit rows.
 *   recordProxyCall: counts an attempted upstream call against rate limits.
 *   recordProxyOutcome: writes the success or failure audit row and records
 *     the learned pattern.
 *
 * Denials carry codes and data, never message text: each caller formats its
 * own response so existing REST and MCP messages stay as they are.
 */

import type { Database } from "bun:sqlite";
import type { SecretsEngine } from "../secrets/engine";
import type { PolicyEngine } from "../policy/engine";
import type { AuditLog } from "../audit/logger";
import type { PatternEngine } from "../patterns/engine";
import type { RateLimiter } from "../rateLimits/limiter";
import type { LeaseManager } from "../lease/manager";
import type { AuthContext } from "../auth/middleware";
import { enforceProxyGates, type GatesBlocked } from "../api/proxyGates";
import { isPrivateHost, pathMatchesAnyPrefix } from "../security/ssrf";
import { splitList } from "../ui/list-validate.js";
import { hostAllowed } from "../security/domainAllowlist";

export interface ProxyDeps {
  secrets: SecretsEngine;
  policies: PolicyEngine;
  audit: AuditLog;
  db?: Database;
  rateLimiter?: RateLimiter;
  leases?: LeaseManager;
  patterns?: PatternEngine;
}

export interface ProxyCall {
  auth: AuthContext;
  sourceIp: string;
  requestId?: string;
  secretPaths: string[];
  /** URL as the caller wrote it, before substitution. Goes in audit metadata. */
  auditUrl: string;
  /** Upstream URL given the secrets resolved so far. */
  resolveUrl: (resolved: Map<string, string>) => string;
  auditAction: "proxy.forward" | "proxy.forward.mcp";
  /** Merged into the metadata of every audit row this call writes. */
  auditExtra?: Record<string, string>;
}

export type ProxyDenial =
  | { code: "policy_denied"; path: string }
  | { code: "gate_blocked"; gate: GatesBlocked }
  | { code: "gates_unavailable"; path: string }
  | { code: "secret_not_found"; path: string }
  | { code: "domain_blocked"; path: string; hostname: string }
  | { code: "path_prefix_blocked"; path: string; resolvedPath: string }
  | { code: "ssrf_blocked"; reason: string }
  | { code: "bad_protocol"; protocol: string }
  | { code: "invalid_url" };

export type ProxyAuthorization =
  | { ok: true; resolved: Map<string, string>; upstreamUrl: string;
      leaseIds: Record<string, string>; roleId: string; tlsInsecure: boolean }
  | { ok: false; denial: ProxyDenial };

export interface ProxyOutcome {
  method: string;
  /** Set when the upstream answered. */
  status?: number;
  redactionCount?: number;
  /**
   * Set when the call failed after authorization (timeout, network, cap).
   * With `status` also set (a streamed response cut after its status was
   * sent), it is recorded as `reason` on the outcome row.
   */
  failureReason?: string;
  /**
   * Failure row carries only target_url and target_path, no method or
   * reason. The MCP tool's historical failure row; REST leaves it unset.
   */
  bareFailureRow?: boolean;
  /** Passed to patterns.record when present. */
  pattern?: { url: string; requestHeaderNames: string[]; requestBody?: unknown; responseBody?: unknown };
}

/**
 * Whether private network proxying is globally allowed. Default true:
 * Gatehouse's primary audience is homelabbers whose services live on
 * private IPs, so the proxy is useless out of the box if these are
 * blocked. Set GATEHOUSE_PROXY_ALLOW_PRIVATE=false to re-enable SSRF
 * blocking (e.g. when exposing Gatehouse on the public internet).
 */
export function allowPrivateGlobally(): boolean {
  const v = (process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE ?? "").toLowerCase();
  return v !== "false";
}

/**
 * Shared SSRF decision. Returns { allowed: true } when the call may proceed,
 * or { allowed: false, reason } when it must be blocked. Both the per-secret
 * override (metadata.allow_private=true) and per-secret force-block
 * (metadata.allow_private=false) are honored.
 */
export function checkPrivateNetworkPolicy(
  hostname: string,
  secretPaths: string[],
  getMeta: (path: string) => { metadata?: Record<string, string> } | null
): { allowed: true } | { allowed: false; reason: string } {
  if (!isPrivateHost(hostname)) return { allowed: true };
  const blocks = secretPaths.some(
    (p) => getMeta(p)?.metadata?.allow_private === "false"
  );
  if (blocks) {
    return {
      allowed: false,
      reason: "This secret has metadata allow_private=false and cannot proxy to private networks. Remove that key or set allow_private=true to allow.",
    };
  }
  const allows = secretPaths.some(
    (p) => getMeta(p)?.metadata?.allow_private === "true"
  );
  if (allowPrivateGlobally() || allows) return { allowed: true };
  return {
    allowed: false,
    reason: "Private network proxying is disabled on this Gatehouse (GATEHOUSE_PROXY_ALLOW_PRIVATE=false). Set metadata allow_private=true on the secret to override, or enable globally.",
  };
}

/** Pathname of the caller-written URL, or "" when it does not parse. */
function auditTargetPath(call: ProxyCall): string {
  try { return new URL(call.auditUrl).pathname; } catch { return ""; }
}

function withExtra(call: ProxyCall, metadata: Record<string, string>): Record<string, string> {
  // Extra first: Gatehouse's own keys (reason, target_*, status, ...) always win.
  return call.auditExtra ? { ...call.auditExtra, ...metadata } : metadata;
}

/** Same predicates enforceProxyGates uses for per-secret limits and approval. */
function secretNeedsGate(meta: { metadata?: Record<string, string> } | null): boolean {
  if (meta?.metadata?.requires_approval === "true") return true;
  const raw = meta?.metadata?.rate_limit_per_minute;
  const perMinute = raw ? parseInt(raw, 10) : NaN;
  return Number.isFinite(perMinute) && perMinute > 0;
}

function deny(denial: ProxyDenial): ProxyAuthorization {
  return { ok: false, denial };
}

export function authorizeProxyCall(deps: ProxyDeps, call: ProxyCall): ProxyAuthorization {
  const { secrets, policies, audit } = deps;
  const { auth, sourceIp, secretPaths } = call;
  const targetPath = auditTargetPath(call);

  // 1. Policy: proxy capability on every referenced secret.
  for (const path of secretPaths) {
    if (!policies.check(auth.policies, path, "proxy")) {
      audit.log({
        identity: auth.identity,
        action: call.auditAction,
        path,
        source_ip: sourceIp,
        metadata: withExtra(call, { target_url: call.auditUrl, target_path: targetPath, reason: "policy_denied" }),
        success: false,
      });
      return deny({ code: "policy_denied", path });
    }
  }

  // 2. Gates: per-AppRole rate limits, per-secret rate limits, approval.
  // Denials come back already audited. Without a limiter, lease manager,
  // and db the gates cannot run: fail closed if any referenced secret needs
  // one, otherwise skip (AppRole-level limits are then not evaluated).
  let roleId = "";
  let leaseIds: Record<string, string> = {};
  if (!(deps.rateLimiter && deps.leases && deps.db)) {
    const gated = secretPaths.find((p) => secretNeedsGate(secrets.getMeta(p)));
    if (gated !== undefined) {
      audit.log({
        identity: auth.identity,
        action: call.auditAction,
        path: gated,
        source_ip: sourceIp,
        metadata: withExtra(call, { target_url: call.auditUrl, target_path: targetPath, reason: "gates_unavailable" }),
        success: false,
      });
      return deny({ code: "gates_unavailable", path: gated });
    }
  } else {
    const gate = enforceProxyGates({
      auth,
      secretPaths,
      sourceIp,
      db: deps.db,
      rateLimiter: deps.rateLimiter,
      leases: deps.leases,
      secrets,
      audit,
      requestId: call.requestId,
      auditExtra: call.auditExtra,
    });
    if (!gate.allowed) return deny({ code: "gate_blocked", gate });
    roleId = gate.roleId;
    leaseIds = gate.leaseIds;
  }

  // 3. Per secret: resolve the value, then check allowed_domains and
  // allowed_path_prefixes against the URL as resolved so far.
  const resolved = new Map<string, string>();
  for (const path of secretPaths) {
    const value = secrets.get(path);
    if (!value) return deny({ code: "secret_not_found", path });
    resolved.set(path, value);

    const resolvedUrl = call.resolveUrl(resolved);
    let parsedResolvedUrl: URL | null = null;
    try { parsedResolvedUrl = new URL(resolvedUrl); } catch { /* invalid URL caught below */ }

    const meta = secrets.getMeta(path);
    if (meta?.metadata?.allowed_domains) {
      const domains: string[] = splitList(meta.metadata.allowed_domains);
      if (domains.length > 0) {
        const { allowed, hostname } = hostAllowed(resolvedUrl, domains);
        if (!allowed) {
          audit.log({
            identity: auth.identity,
            action: call.auditAction,
            path,
            source_ip: sourceIp,
            metadata: withExtra(call, {
              target_url: call.auditUrl,
              target_path: targetPath,
              hostname,
              reason: "domain_blocked",
              allowed_domains: meta.metadata.allowed_domains,
            }),
            success: false,
          });
          return deny({ code: "domain_blocked", path, hostname });
        }
      }
    }

    if (meta?.metadata?.allowed_path_prefixes) {
      const prefixes: string[] = splitList(meta.metadata.allowed_path_prefixes);
      if (prefixes.length > 0) {
        const resolvedPath = parsedResolvedUrl?.pathname ?? targetPath;
        if (!pathMatchesAnyPrefix(resolvedPath, prefixes)) {
          audit.log({
            identity: auth.identity,
            action: call.auditAction,
            path,
            source_ip: sourceIp,
            metadata: withExtra(call, {
              target_url: call.auditUrl,
              target_path: targetPath,
              reason: "path_prefix_blocked",
              allowed_path_prefixes: meta.metadata.allowed_path_prefixes,
            }),
            success: false,
          });
          return deny({ code: "path_prefix_blocked", path, resolvedPath });
        }
      }
    }
  }

  // 4. Private-network policy, then 5. protocol, on the fully resolved URL.
  const upstreamUrl = call.resolveUrl(resolved);
  let parsedUpstream: URL;
  try {
    parsedUpstream = new URL(upstreamUrl);
  } catch {
    return deny({ code: "invalid_url" });
  }
  const ssrf = checkPrivateNetworkPolicy(parsedUpstream.hostname, secretPaths, (p) => secrets.getMeta(p));
  if (!ssrf.allowed) {
    audit.log({
      identity: auth.identity,
      action: call.auditAction,
      path: secretPaths.join(","),
      source_ip: sourceIp,
      metadata: withExtra(call, { target_host: parsedUpstream.hostname, target_path: targetPath, reason: "ssrf_blocked" }),
      success: false,
    });
    return deny({ code: "ssrf_blocked", reason: ssrf.reason });
  }
  if (!["http:", "https:"].includes(parsedUpstream.protocol)) {
    return deny({ code: "bad_protocol", protocol: parsedUpstream.protocol });
  }

  const tlsInsecure = secretPaths.some(
    (p) => secrets.getMeta(p)?.metadata?.tls_allow_insecure === "true"
  );

  return { ok: true, resolved, upstreamUrl, leaseIds, roleId, tlsInsecure };
}

/**
 * Counts the call against AppRole and per-secret rate-limit buckets. Call
 * once, when the upstream fetch has been attempted: upstream 4xx/5xx,
 * timeouts, and oversized bodies all count. Pre-forward denials do not.
 */
export function recordProxyCall(deps: ProxyDeps, call: ProxyCall, authz: { roleId: string }): void {
  if (deps.rateLimiter) deps.rateLimiter.recordCall(authz.roleId, call.secretPaths);
}

/**
 * Writes the success or failure audit row and records the pattern. The
 * resolved upstream URL is used only for its hostname: it may carry secret
 * values in its path, so it is never logged.
 */
export function recordProxyOutcome(
  deps: ProxyDeps,
  call: ProxyCall,
  authz: { leaseIds: Record<string, string>; upstreamUrl: string },
  outcome: ProxyOutcome
): void {
  const { auth, sourceIp, secretPaths } = call;
  const targetPath = auditTargetPath(call);

  if (outcome.status === undefined) {
    deps.audit.log({
      identity: auth.identity,
      action: call.auditAction,
      path: secretPaths.join(","),
      source_ip: sourceIp,
      metadata: withExtra(call, outcome.bareFailureRow
        ? { target_url: call.auditUrl, target_path: targetPath }
        : {
            target_url: call.auditUrl,
            target_path: targetPath,
            method: outcome.method,
            reason: outcome.failureReason ?? "unknown",
          }),
      success: false,
    });
    return;
  }

  const meta: Record<string, string> = {
    target_host: new URL(authz.upstreamUrl).hostname,
    target_path: targetPath,
    target_url: call.auditUrl,
    method: outcome.method,
    status: String(outcome.status),
  };
  const leaseIdsList = Object.values(authz.leaseIds);
  if (leaseIdsList.length > 0) meta.lease_id = leaseIdsList.join(",");
  meta.redaction_count = String(outcome.redactionCount ?? 0);
  if (outcome.failureReason) meta.reason = outcome.failureReason;
  // Surface the authorizing lease_id as the top-level audit column when
  // exactly one approval lease gated this call, so the audit UI can filter by
  // lease without parsing metadata. Multi-lease calls keep the comma-joined
  // list in metadata only.
  const topLeaseId = leaseIdsList.length === 1 ? leaseIdsList[0] : undefined;
  deps.audit.log({
    identity: auth.identity,
    action: call.auditAction,
    path: secretPaths.join(","),
    source_ip: sourceIp,
    ...(topLeaseId ? { lease_id: topLeaseId } : {}),
    metadata: withExtra(call, meta),
    // A status with a reason is a response that was cut (byte_cap,
    // idle_timeout, upstream_error, client_abort): not a success. Only
    // passthrough passes both; /v1/proxy and MCP rows are unchanged.
    ...(outcome.failureReason ? { success: false } : {}),
  });

  if (deps.patterns && outcome.pattern) {
    try {
      deps.patterns.record({
        secret_paths: secretPaths,
        method: outcome.method,
        url: outcome.pattern.url,
        request_headers: outcome.pattern.requestHeaderNames,
        request_body: outcome.pattern.requestBody,
        response_status: outcome.status,
        response_body: outcome.pattern.responseBody,
        identity: auth.identity,
      });
    } catch {
      // Pattern recording must never fail a proxy call
    }
  }
}
