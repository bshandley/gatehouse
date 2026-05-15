import { describe, test, expect } from "bun:test";
import { buildMetadata, hydrateMetadata, DEFAULT_STATE } from "../src/ui/secret-form-metadata.js";

describe("buildMetadata", () => {
  test("default state produces empty metadata", () => {
    expect(buildMetadata(DEFAULT_STATE())).toEqual({});
  });

  test("requires_approval=true writes the string 'true'", () => {
    const s = DEFAULT_STATE();
    s.requires_approval = true;
    expect(buildMetadata(s)).toEqual({ requires_approval: "true" });
  });

  test("requires_approval=false omits the key", () => {
    const s = DEFAULT_STATE();
    s.requires_approval = false;
    expect(buildMetadata(s)).toEqual({});
  });

  test("auth_scheme=none omits the key", () => {
    const s = DEFAULT_STATE();
    s.auth_scheme = "none";
    expect(buildMetadata(s)).toEqual({});
  });

  test("auth_scheme=bearer writes 'bearer'", () => {
    const s = DEFAULT_STATE();
    s.auth_scheme = "bearer";
    expect(buildMetadata(s)).toEqual({ auth_scheme: "bearer" });
  });

  test("auth_scheme=header without header_name throws", () => {
    const s = DEFAULT_STATE();
    s.auth_scheme = "header";
    s.header_name = "";
    expect(() => buildMetadata(s)).toThrow(/header_name required/);
  });

  test("auth_scheme=header with header_name writes both", () => {
    const s = DEFAULT_STATE();
    s.auth_scheme = "header";
    s.header_name = "X-API-Key";
    expect(buildMetadata(s)).toEqual({ auth_scheme: "header", header_name: "X-API-Key" });
  });

  test("description trims and omits when blank", () => {
    const s = DEFAULT_STATE();
    s.description = "   ";
    expect(buildMetadata(s)).toEqual({});
    s.description = "  Anthropic API key  ";
    expect(buildMetadata(s)).toEqual({ description: "Anthropic API key" });
  });

  test("rate_limit_per_minute parses integer; non-numeric is omitted", () => {
    const s = DEFAULT_STATE();
    s.rate_limit_per_minute = "60";
    expect(buildMetadata(s)).toEqual({ rate_limit_per_minute: "60" });
    s.rate_limit_per_minute = "abc";
    expect(buildMetadata(s)).toEqual({});
    s.rate_limit_per_minute = "0";
    expect(buildMetadata(s)).toEqual({});
  });

  test("auto_approve_ttl_seconds without auto_approve_from_ip is omitted", () => {
    const s = DEFAULT_STATE();
    s.auto_approve_from_ip = "";
    s.auto_approve_ttl_seconds = "3600";
    expect(buildMetadata(s)).toEqual({});
  });

  test("auto_approve_from_ip without TTL writes only the IP", () => {
    const s = DEFAULT_STATE();
    s.auto_approve_from_ip = "10.0.0.5";
    s.auto_approve_ttl_seconds = "";
    expect(buildMetadata(s)).toEqual({ auto_approve_from_ip: "10.0.0.5" });
  });

  test("auto_approve_from_ip + TTL writes both", () => {
    const s = DEFAULT_STATE();
    s.auto_approve_from_ip = "10.0.0.5";
    s.auto_approve_ttl_seconds = "3600";
    expect(buildMetadata(s)).toEqual({ auto_approve_from_ip: "10.0.0.5", auto_approve_ttl_seconds: "3600" });
  });

  test("boolean toggles write 'true' or omit", () => {
    const s = DEFAULT_STATE();
    s.allow_private = true;
    s.tls_allow_insecure = false;
    expect(buildMetadata(s)).toEqual({ allow_private: "true" });
  });

  test("text fields are trimmed; empty after trim is omitted", () => {
    const s = DEFAULT_STATE();
    s.allowed_domains = "  api.example.com, *.example.org  ";
    s.allowed_path_prefixes = "   ";
    expect(buildMetadata(s)).toEqual({ allowed_domains: "api.example.com, *.example.org" });
  });

  test("custom kv rows are appended, structured fields win on key collision", () => {
    const s = DEFAULT_STATE();
    s.description = "from form";
    s.custom = [
      ["description", "from kv"],
      ["x-internal", "team-eng"],
      ["", "skip me"],
    ];
    expect(buildMetadata(s)).toEqual({ description: "from form", "x-internal": "team-eng" });
  });
});

describe("hydrateMetadata", () => {
  test("empty metadata produces default state", () => {
    expect(hydrateMetadata({})).toEqual(DEFAULT_STATE());
  });

  test("known keys populate their controls", () => {
    const s = hydrateMetadata({
      description: "Anthropic key",
      requires_approval: "true",
      auth_scheme: "bearer",
      allowed_domains: "api.example.com",
      rate_limit_per_minute: "60",
    });
    expect(s.description).toBe("Anthropic key");
    expect(s.requires_approval).toBe(true);
    expect(s.auth_scheme).toBe("bearer");
    expect(s.allowed_domains).toBe("api.example.com");
    expect(s.rate_limit_per_minute).toBe("60");
    expect(s.custom).toEqual([]);
  });

  test("requires_approval=false hydrates as off (will normalize on save)", () => {
    const s = hydrateMetadata({ requires_approval: "false" });
    expect(s.requires_approval).toBe(false);
  });

  test("unknown keys land in custom rows", () => {
    const s = hydrateMetadata({
      description: "known",
      "x-team": "platform",
      "x-cost-center": "1234",
    });
    expect(s.description).toBe("known");
    expect(s.custom).toEqual([["x-team", "platform"], ["x-cost-center", "1234"]]);
  });

  test("unknown auth_scheme value falls back to none + becomes a custom row", () => {
    const s = hydrateMetadata({ auth_scheme: "weird" });
    expect(s.auth_scheme).toBe("none");
    expect(s.custom).toEqual([["auth_scheme", "weird"]]);
  });

  test("round-trip: build(hydrate(x)) == x for canonical metadata", () => {
    const original = {
      description: "Anthropic key",
      requires_approval: "true",
      auth_scheme: "header",
      header_name: "X-API-Key",
      allowed_domains: "api.example.com",
      allow_private: "true",
      rate_limit_per_minute: "60",
      "x-team": "platform",
    };
    expect(buildMetadata(hydrateMetadata(original))).toEqual(original);
  });

  test("round-trip normalizes legacy requires_approval=false to omitted", () => {
    const out = buildMetadata(hydrateMetadata({ requires_approval: "false" }));
    expect(out).toEqual({});
  });

  test("round-trip normalizes orphan auto_approve_ttl_seconds", () => {
    const out = buildMetadata(hydrateMetadata({ auto_approve_ttl_seconds: "3600" }));
    expect(out).toEqual({});
  });

  test("unknown auth_scheme preserves header_name via custom rows", () => {
    const s = hydrateMetadata({ auth_scheme: "weird", header_name: "X-Foo" });
    expect(s.auth_scheme).toBe("none");
    expect(s.header_name).toBe("");
    expect(s.custom).toEqual([["auth_scheme", "weird"], ["header_name", "X-Foo"]]);
  });

  test("round-trip preserves header_name paired with unknown auth_scheme", () => {
    const original = { auth_scheme: "weird", header_name: "X-Foo" };
    expect(buildMetadata(hydrateMetadata(original))).toEqual(original);
  });
});
