import { describe, test, expect } from "bun:test";
import { scrubResponseBody, secretRedactionValues } from "../src/security/ssrf";

describe("scrubResponseBody", () => {
  test("redacts a raw secret value echoed by the upstream", () => {
    const out = scrubResponseBody(
      "your token is sk-test-openai-key-123 ok",
      secretRedactionValues(["sk-test-openai-key-123"])
    );
    expect(out.body).not.toContain("sk-test-openai-key-123");
    expect(out.body).toContain("[REDACTED]");
    expect(out.count).toBe(1);
  });

  test("redacts the base64 form of a basic-auth credential", () => {
    const cred = "admin:SuperSecretPass99";
    const encoded = btoa(cred);
    const upstreamBody = `{"error":"invalid auth","received":"Basic ${encoded}"}`;

    const out = scrubResponseBody(upstreamBody, secretRedactionValues([cred]));

    expect(out.body).not.toContain(encoded);
    expect(out.body).toContain("[REDACTED]");
    expect(out.count).toBe(1);
  });

  test("does not mangle short values below the 8-char floor", () => {
    const out = scrubResponseBody("price is 1234567", secretRedactionValues(["1234567"]));
    expect(out.body).toBe("price is 1234567");
    expect(out.count).toBe(0);
  });

  test("leaves unrelated text untouched and reports zero redactions", () => {
    const clean = "all good, nothing secret here";
    const out = scrubResponseBody(clean, secretRedactionValues(["sk-test-openai-key-123"]));
    expect(out.body).toBe(clean);
    expect(out.count).toBe(0);
  });

  test("counts every occurrence of a repeated secret", () => {
    const v = "sk-test-openai-key-123";
    const out = scrubResponseBody(`${v} and again ${v}`, secretRedactionValues([v]));
    expect(out.count).toBe(2);
    expect(out.body).not.toContain(v);
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
