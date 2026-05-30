import { describe, test, expect } from "bun:test";
import { scrubResponseBody, secretRedactionValues } from "../src/security/ssrf";

describe("scrubResponseBody", () => {
  test("redacts a raw secret value echoed by the upstream", () => {
    const out = scrubResponseBody(
      "your token is sk-test-openai-key-123 ok",
      secretRedactionValues(["sk-test-openai-key-123"])
    );
    expect(out).not.toContain("sk-test-openai-key-123");
    expect(out).toContain("[REDACTED]");
  });

  test("redacts the base64 form of a basic-auth credential", () => {
    // The basic: inject shorthand puts `Basic <base64(user:pass)>` on the wire.
    // An upstream that echoes the Authorization header must not leak it back.
    const cred = "admin:SuperSecretPass99";
    const encoded = btoa(cred);
    const upstreamBody = `{"error":"invalid auth","received":"Basic ${encoded}"}`;

    const out = scrubResponseBody(upstreamBody, secretRedactionValues([cred]));

    expect(out).not.toContain(encoded);
    expect(out).toContain("[REDACTED]");
  });

  test("does not mangle short values below the 8-char floor", () => {
    const out = scrubResponseBody("price is 1234567", secretRedactionValues(["1234567"]));
    expect(out).toBe("price is 1234567");
  });

  test("leaves unrelated text untouched", () => {
    const clean = "all good, nothing secret here";
    expect(scrubResponseBody(clean, secretRedactionValues(["sk-test-openai-key-123"]))).toBe(clean);
  });
});

describe("secretRedactionValues", () => {
  test("includes each raw value plus its base64 encoding", () => {
    const vals = secretRedactionValues(["admin:SuperSecretPass99"]);
    expect(vals).toContain("admin:SuperSecretPass99");
    expect(vals).toContain(btoa("admin:SuperSecretPass99"));
  });

  test("skips empty values", () => {
    expect(secretRedactionValues(["", "x"])).toEqual(["x", btoa("x")]);
  });
});
