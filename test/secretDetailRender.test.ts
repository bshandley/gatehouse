import { describe, test, expect } from "bun:test";
import {
  referenceChipHtml,
  postureChips,
  postureChipsHtml,
  relativeTime,
  formatActivityRow,
  formatLeaseRow,
  emptyStateStats,
  emptyStateStatsLine,
  treeAuthChip,
} from "../src/ui/secret-detail-render.js";

describe("referenceChipHtml", () => {
  test("includes the {{secret:<path>}} text verbatim", () => {
    const html = referenceChipHtml("api-keys/example");
    expect(html).toContain("{{secret:api-keys/example}}");
    expect(html).toContain("detail-ref-chip");
  });

  test("HTML-escapes the path", () => {
    const html = referenceChipHtml('weird"path');
    expect(html).not.toContain('weird"path');
    expect(html).toContain("&quot;");
  });
});

describe("postureChips", () => {
  test("empty metadata produces no chips", () => {
    expect(postureChips({})).toEqual([]);
  });

  test("bearer auth + allowed_domains produces AUTH and SCOPE chips", () => {
    const chips = postureChips({ auth_scheme: "bearer", allowed_domains: "api.example.com" });
    expect(chips).toEqual([
      { label: "AUTH", value: "bearer", variant: "neutral" },
      { label: "SCOPE", value: "api.example.com", variant: "neutral" },
    ]);
  });

  test("header auth includes header_name in the AUTH value", () => {
    const chips = postureChips({ auth_scheme: "header", header_name: "X-API-Key", allowed_domains: "x" });
    expect(chips[0]).toEqual({ label: "AUTH", value: "header:X-API-Key", variant: "neutral" });
  });

  test("auth without allowed_domains adds inferred warning chip", () => {
    const chips = postureChips({ auth_scheme: "bearer" });
    expect(chips).toContainEqual({ label: "SCOPE", value: "no allowed_domains", variant: "warn" });
  });

  test("requires_approval=true is an accent chip", () => {
    const chips = postureChips({ requires_approval: "true" });
    expect(chips).toContainEqual({ label: "APPROVAL", value: "required", variant: "accent" });
  });

  test("requires_approval=false omits the chip", () => {
    expect(postureChips({ requires_approval: "false" })).toEqual([]);
  });

  test("allow_private=true is a warn chip", () => {
    const chips = postureChips({ allow_private: "true" });
    expect(chips).toContainEqual({ label: "PRIVATE", value: "private IPs ok", variant: "warn" });
  });

  test("tls_allow_insecure=true is a warn chip", () => {
    const chips = postureChips({ tls_allow_insecure: "true" });
    expect(chips).toContainEqual({ label: "TLS", value: "insecure TLS ok", variant: "warn" });
  });

  test("rate_limit_per_minute renders as Nrate per min", () => {
    const chips = postureChips({ rate_limit_per_minute: "60" });
    expect(chips).toContainEqual({ label: "RATE", value: "60 / min", variant: "neutral" });
  });

  test("auto-approval IP + TTL render as separate warn chips", () => {
    const chips = postureChips({ auto_approve_from_ip: "10.0.0.5", auto_approve_ttl_seconds: "3600" });
    expect(chips).toContainEqual({ label: "AUTO-IP", value: "10.0.0.5", variant: "warn" });
    expect(chips).toContainEqual({ label: "AUTO-TTL", value: "3600s", variant: "warn" });
  });

  test("path prefixes render as PATHS chip", () => {
    const chips = postureChips({ allowed_path_prefixes: "/v1/, /v2/" });
    expect(chips).toContainEqual({ label: "PATHS", value: "/v1/, /v2/", variant: "neutral" });
  });

  test("full posture produces correct ordering", () => {
    const chips = postureChips({
      auth_scheme: "bearer",
      allowed_domains: "api.example.com",
      allowed_path_prefixes: "/v1/",
      rate_limit_per_minute: "60",
      requires_approval: "true",
    });
    expect(chips.map(c => c.label)).toEqual(["AUTH", "SCOPE", "PATHS", "RATE", "APPROVAL"]);
  });
});

describe("postureChipsHtml", () => {
  test("returns empty string when no chips", () => {
    expect(postureChipsHtml({})).toBe("");
  });

  test("wraps chips in a posture-chips container with section heading", () => {
    const html = postureChipsHtml({ auth_scheme: "bearer", allowed_domains: "x" });
    expect(html).toContain("POSTURE");
    expect(html).toContain("posture-chips");
    expect(html).toContain("posture-chip");
    expect(html).toContain("AUTH");
    expect(html).toContain("bearer");
  });

  test("warn variant renders the is-warn class", () => {
    const html = postureChipsHtml({ allow_private: "true" });
    expect(html).toContain("is-warn");
  });

  test("accent variant renders the is-accent class", () => {
    const html = postureChipsHtml({ requires_approval: "true" });
    expect(html).toContain("is-accent");
  });
});

describe("relativeTime", () => {
  const now = Date.now();
  const iso = (offsetMs: number) => new Date(now - offsetMs).toISOString();

  test("returns empty string for falsy input", () => {
    expect(relativeTime("")).toBe("");
    expect(relativeTime(null as any)).toBe("");
    expect(relativeTime(undefined as any)).toBe("");
  });

  test("returns 'now' for very recent times", () => {
    expect(relativeTime(iso(500))).toBe("now");
  });

  test("returns Ns for seconds", () => {
    expect(relativeTime(iso(30_000))).toBe("30s ago");
  });

  test("returns Nm ago for minutes", () => {
    expect(relativeTime(iso(5 * 60_000))).toBe("5m ago");
  });

  test("returns Nh ago for hours", () => {
    expect(relativeTime(iso(3 * 3600_000))).toBe("3h ago");
  });

  test("returns Nd ago for days", () => {
    expect(relativeTime(iso(2 * 86_400_000))).toBe("2d ago");
  });

  test("returns Nw ago for weeks", () => {
    expect(relativeTime(iso(3 * 7 * 86_400_000))).toBe("3w ago");
  });

  test("returns Nmo ago for months", () => {
    expect(relativeTime(iso(3 * 30 * 86_400_000))).toBe("3mo ago");
  });
});

describe("formatActivityRow", () => {
  test("renders time, action, identity, ok tag", () => {
    const ts = new Date(Date.now() - 2 * 3600_000).toISOString();
    const html = formatActivityRow({ timestamp: ts, action: "secret.read", identity: "bradley", success: true });
    expect(html).toContain("2h ago");
    expect(html).toContain("secret.read");
    expect(html).toContain("bradley");
    expect(html).toContain("is-ok");
  });

  test("success=false renders is-fail tag", () => {
    const ts = new Date(Date.now() - 60_000).toISOString();
    const html = formatActivityRow({ timestamp: ts, action: "secret.read", identity: "bradley", success: false });
    expect(html).toContain("is-fail");
    expect(html).toContain("fail");
  });

  test("missing identity falls back to '-'", () => {
    const ts = new Date(Date.now() - 60_000).toISOString();
    const html = formatActivityRow({ timestamp: ts, action: "secret.read", identity: "", success: true });
    expect(html).toContain(">-<");
  });
});

describe("formatLeaseRow", () => {
  test("renders identity + expires", () => {
    const html = formatLeaseRow({ identity: "agent-alice", expires_at: "2026-05-15T14:00:00Z", status: "active" }, false);
    expect(html).toContain("agent-alice");
    expect(html).toContain("expires");
  });

  test("appends (gated) tag when requires_approval && status=approved", () => {
    const html = formatLeaseRow({ identity: "agent-bob", expires_at: "2026-05-15T14:00:00Z", status: "approved" }, true);
    expect(html).toContain("(gated)");
  });

  test("no (gated) tag when secret doesn't require approval", () => {
    const html = formatLeaseRow({ identity: "agent-bob", expires_at: "2026-05-15T14:00:00Z", status: "approved" }, false);
    expect(html).not.toContain("(gated)");
  });
});

describe("emptyStateStats", () => {
  const recent = new Date(Date.now() - 2 * 86_400_000).toISOString();
  const old = new Date(Date.now() - 30 * 86_400_000).toISOString();

  test("zero secrets", () => {
    expect(emptyStateStats([])).toEqual({ total: 0, gated: 0, touchedThisWeek: 0 });
  });

  test("counts gated + touched correctly", () => {
    const secrets = [
      { metadata: { requires_approval: "true" }, updated_at: recent },
      { metadata: {}, updated_at: recent },
      { metadata: { requires_approval: "true" }, updated_at: old },
      { metadata: {}, updated_at: old },
    ];
    expect(emptyStateStats(secrets)).toEqual({ total: 4, gated: 2, touchedThisWeek: 2 });
  });

  test("emptyStateStatsLine returns empty string when zero secrets", () => {
    expect(emptyStateStatsLine([])).toBe("");
  });

  test("emptyStateStatsLine renders the counts when non-empty", () => {
    const secrets = [{ metadata: {}, updated_at: recent }];
    const line = emptyStateStatsLine(secrets);
    expect(line).toContain("1 secrets");
    expect(line).toContain("0 require approval");
    expect(line).toContain("1 touched this week");
  });
});

describe("treeAuthChip", () => {
  test("returns empty string when auth_scheme is absent", () => {
    expect(treeAuthChip({})).toBe("");
    expect(treeAuthChip(undefined as any)).toBe("");
  });

  test("returns empty string when auth_scheme is 'none'", () => {
    expect(treeAuthChip({ auth_scheme: "none" })).toBe("");
  });

  test("renders bearer", () => {
    const html = treeAuthChip({ auth_scheme: "bearer" });
    expect(html).toContain("[bearer]");
    expect(html).toContain("tree-item-auth");
  });

  test("renders header:Name when scheme=header", () => {
    const html = treeAuthChip({ auth_scheme: "header", header_name: "X-API-Key" });
    expect(html).toContain("[header:X-API-Key]");
  });

  test("renders bare header when scheme=header but no header_name", () => {
    const html = treeAuthChip({ auth_scheme: "header" });
    expect(html).toContain("[header]");
  });
});
