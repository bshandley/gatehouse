import { describe, test, expect } from "bun:test";
import { scrubValue, containsCredentials } from "../src/scrub/scrubber";

describe("scrubber", () => {
  test("leaves clean text unchanged", () => {
    const clean = "This is perfectly safe text with no secrets.";
    const result = scrubValue(clean);
    expect(result.scrubbed).toBe(clean);
    expect(result.redactions.length).toBe(0);
  });

  test("containsCredentials detects patterns", () => {
    expect(containsCredentials("safe text")).toBe(false);
    expect(containsCredentials("sk-proj-abc123def456ghi789jkl012mno")).toBe(
      true
    );
  });

  // OpenAI keys
  test("redacts OpenAI project keys (sk-proj-)", () => {
    const result = scrubValue(
      "key is sk-proj-abc123def456ghi789jkl012mno"
    );
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(result.scrubbed).not.toContain("abc123def456ghi789jkl012mno");
    expect(result.redactions.length).toBe(1);
    expect(result.redactions[0].type).toBe("openai_key");
  });

  test("redacts legacy OpenAI keys (sk-)", () => {
    const key = "sk-" + "A".repeat(48);
    const result = scrubValue(`my key: ${key}`);
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(result.redactions.length).toBeGreaterThanOrEqual(1);
  });

  // Anthropic keys
  test("redacts Anthropic keys (sk-ant-)", () => {
    const result = scrubValue(
      "sk-ant-api03-abcdefghijklmnopqrstuvwx"
    );
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(
      result.redactions.some((r) => r.type === "anthropic_key")
    ).toBe(true);
  });

  // GitHub tokens
  test("redacts GitHub PATs (ghp_)", () => {
    const token = "ghp_" + "A".repeat(36);
    const result = scrubValue(`token: ${token}`);
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(
      result.redactions.some((r) => r.type === "github_pat")
    ).toBe(true);
  });

  test("redacts GitHub OAuth tokens (gho_)", () => {
    const token = "gho_" + "B".repeat(36);
    const result = scrubValue(token);
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(
      result.redactions.some((r) => r.type === "github_token")
    ).toBe(true);
  });

  test("redacts GitHub App tokens (ghs_)", () => {
    const token = "ghs_" + "C".repeat(36);
    const result = scrubValue(token);
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(
      result.redactions.some((r) => r.type === "github_app")
    ).toBe(true);
  });

  // AWS keys
  test("redacts AWS access keys", () => {
    const result = scrubValue("AKIAIOSFODNN7EXAMPLE");
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(
      result.redactions.some((r) => r.type === "aws_access_key")
    ).toBe(true);
  });

  // Stripe keys
  test("redacts Stripe live keys", () => {
    const key = "sk_live_" + "a".repeat(24);
    const result = scrubValue(`stripe: ${key}`);
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(
      result.redactions.some((r) => r.type === "stripe_key")
    ).toBe(true);
  });

  test("redacts Stripe test keys", () => {
    const key = "sk_test_" + "b".repeat(24);
    const result = scrubValue(key);
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(
      result.redactions.some((r) => r.type === "stripe_test")
    ).toBe(true);
  });

  // Slack tokens
  test("redacts Slack bot tokens (xoxb-)", () => {
    const token = "xoxb-123456789012-123456789012-abcdefghij";
    const result = scrubValue(token);
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(
      result.redactions.some((r) => r.type === "slack_token")
    ).toBe(true);
  });

  test("redacts Slack user tokens (xoxp-)", () => {
    const token = "xoxp-123456789012-123456789012-abcdefghij";
    const result = scrubValue(token);
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(
      result.redactions.some((r) => r.type === "slack_user")
    ).toBe(true);
  });

  // Bearer tokens
  test("redacts Bearer tokens", () => {
    const result = scrubValue(
      "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123"
    );
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(
      result.redactions.some((r) => r.type === "generic_bearer")
    ).toBe(true);
  });

  // Connection strings
  test("redacts PostgreSQL connection strings", () => {
    const result = scrubValue(
      "postgres://user:pass@host:5432/dbname"
    );
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(
      result.redactions.some((r) => r.type === "connection_string")
    ).toBe(true);
  });

  test("redacts MongoDB connection strings", () => {
    const result = scrubValue(
      "mongodb://user:pass@host:27017/dbname"
    );
    expect(result.scrubbed).toContain("***REDACTED***");
  });

  test("redacts Redis connection strings", () => {
    const result = scrubValue("redis://user:password@redis-host:6379");
    expect(result.scrubbed).toContain("***REDACTED***");
  });

  // Basic auth URLs
  test("redacts basic auth in URLs", () => {
    const result = scrubValue(
      "https://admin:secretpass@internal.example.com/api"
    );
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(
      result.redactions.some((r) => r.type === "basic_auth_url")
    ).toBe(true);
  });

  // Private keys
  test("redacts RSA private keys", () => {
    const key = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWep4PAtGoRBh
-----END RSA PRIVATE KEY-----`;
    const result = scrubValue(`key:\n${key}`);
    expect(result.scrubbed).toContain("***REDACTED***");
    expect(
      result.redactions.some((r) => r.type === "private_key")
    ).toBe(true);
  });

  test("redacts generic private keys", () => {
    const key = `-----BEGIN PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn
-----END PRIVATE KEY-----`;
    const result = scrubValue(key);
    expect(result.scrubbed).toContain("***REDACTED***");
  });

  // Multiple redactions
  test("handles multiple credentials in one text", () => {
    const text = `OpenAI: sk-proj-abc123def456ghi789jkl012mno
GitHub: ghp_${"A".repeat(36)}
AWS: AKIAIOSFODNN7EXAMPLE`;
    const result = scrubValue(text);
    expect(result.redactions.length).toBeGreaterThanOrEqual(3);
    expect(result.scrubbed).not.toContain("abc123def456ghi789jkl012mno");
  });

  // Prefix preservation
  test("preserves prefix in redacted output", () => {
    const result = scrubValue("ghp_" + "A".repeat(36));
    // Scrubber keeps first 6 chars as prefix
    expect(result.scrubbed).toStartWith("ghp_AA");
    expect(result.scrubbed).toContain("***REDACTED***");
  });

  test("handles empty string", () => {
    const result = scrubValue("");
    expect(result.scrubbed).toBe("");
    expect(result.redactions.length).toBe(0);
  });
});
