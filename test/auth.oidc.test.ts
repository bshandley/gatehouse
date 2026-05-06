import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { _resetCachesForTests, getDiscovery } from "../src/auth/oidc";
import { buildAuthUrl, generateLoginParams } from "../src/auth/oidc";
import { exchangeAndVerify, fetchUserinfo } from "../src/auth/oidc";
import { startFakeIdp } from "./helpers/fake-oidc";

describe("OIDC discovery cache", () => {
  let originalFetch: typeof fetch;
  let fetchCalls: string[];

  beforeEach(() => {
    fetchCalls = [];
    _resetCachesForTests();
    originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: any, init?: any) => {
      const url = typeof input === "string" ? input : input.url;
      fetchCalls.push(url);
      if (url.endsWith("/.well-known/openid-configuration")) {
        return new Response(
          JSON.stringify({
            issuer: "https://idp.test",
            authorization_endpoint: "https://idp.test/authorize",
            token_endpoint: "https://idp.test/token",
            jwks_uri: "https://idp.test/jwks",
            userinfo_endpoint: "https://idp.test/userinfo",
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      return new Response("not found", { status: 404 });
    }) as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test("first call hits network, second call is cached", async () => {
    await getDiscovery("https://idp.test");
    await getDiscovery("https://idp.test");
    expect(fetchCalls.length).toBe(1);
  });

  test("returns parsed metadata", async () => {
    const meta = await getDiscovery("https://idp.test");
    expect(meta.authorization_endpoint).toBe("https://idp.test/authorize");
    expect(meta.token_endpoint).toBe("https://idp.test/token");
    expect(meta.jwks_uri).toBe("https://idp.test/jwks");
  });

  test("network failure surfaces as a thrown error", async () => {
    globalThis.fetch = (async () => new Response("server error", { status: 500 })) as typeof fetch;
    await expect(getDiscovery("https://broken.test")).rejects.toThrow();
  });
});

describe("OIDC authorization URL builder", () => {
  let savedFetch: typeof fetch;
  beforeEach(() => { savedFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = savedFetch; });

  test("includes state, nonce, code_challenge, S256, scopes", async () => {
    _resetCachesForTests();
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          issuer: "https://idp.test",
          authorization_endpoint: "https://idp.test/authorize",
          token_endpoint: "https://idp.test/token",
          jwks_uri: "https://idp.test/jwks",
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      )) as typeof fetch;

    const params = await generateLoginParams();
    const url = await buildAuthUrl({
      config: {
        issuer: "https://idp.test",
        client_id: "test-client",
        client_secret: "secret",
        redirect_uri: "http://gatehouse.test/v1/auth/sso/callback",
        scopes: "openid profile email",
      },
      state: params.state,
      nonce: params.nonce,
      codeVerifier: params.codeVerifier,
    });

    expect(url.origin + url.pathname).toBe("https://idp.test/authorize");
    expect(url.searchParams.get("client_id")).toBe("test-client");
    expect(url.searchParams.get("redirect_uri")).toBe("http://gatehouse.test/v1/auth/sso/callback");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("scope")).toBe("openid profile email");
    expect(url.searchParams.get("state")).toBe(params.state);
    expect(url.searchParams.get("nonce")).toBe(params.nonce);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    const challenge = url.searchParams.get("code_challenge");
    expect(challenge).toBeTruthy();
    expect(challenge?.length).toBeGreaterThan(20);
  });

  test("generateLoginParams produces unique values per call", async () => {
    const a = await generateLoginParams();
    const b = await generateLoginParams();
    expect(a.state).not.toBe(b.state);
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
  });
});

describe("OIDC code exchange + ID token verify", () => {
  let savedFetch: typeof fetch;

  beforeEach(() => {
    savedFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = savedFetch;
  });

  test("happy path returns claims and access token", async () => {
    _resetCachesForTests();
    // Restore real fetch so oauth4webapi can hit the fake IdP over real HTTP.
    globalThis.fetch = savedFetch;
    const idp = await startFakeIdp({ clientId: "test-client", clientSecret: "test-secret" });
    try {
      idp.setNextUser({ sub: "u1", email: "alice@example.com", email_verified: true });

      const cfg = {
        issuer: idp.url,
        client_id: "test-client",
        client_secret: "test-secret",
        redirect_uri: "http://gatehouse.test/v1/auth/sso/callback",
        scopes: "openid profile email",
      };
      idp.setNextNonce("n-1");
      const result = await exchangeAndVerify({
        config: cfg,
        callbackParams: new URLSearchParams({ code: "test-code" }),
        codeVerifier: "v".repeat(43),
        expectedNonce: "n-1",
      });
      expect(result.accessToken).toStartWith("fake-access-token-");
      expect(result.claims.sub).toBe("u1");

      const userinfo = await fetchUserinfo({
        config: cfg,
        accessToken: result.accessToken,
        expectedSubject: result.claims.sub as string,
      });
      expect(userinfo.email).toBe("alice@example.com");
      expect(userinfo.email_verified).toBe(true);
    } finally {
      await idp.stop();
    }
  });

  test("rejects ID token with wrong audience", async () => {
    _resetCachesForTests();
    globalThis.fetch = savedFetch;
    const idp = await startFakeIdp({ clientId: "test-client", clientSecret: "test-secret" });
    try {
      idp.setNextAud("wrong-audience");
      idp.setNextNonce("n-2");
      await expect(
        exchangeAndVerify({
          config: {
            issuer: idp.url,
            client_id: "test-client",
            client_secret: "test-secret",
            redirect_uri: "http://gatehouse.test/v1/auth/sso/callback",
            scopes: "openid profile email",
          },
          callbackParams: new URLSearchParams({ code: "test-code" }),
          codeVerifier: "v".repeat(43),
          expectedNonce: "n-2",
        })
      ).rejects.toThrow();
    } finally {
      await idp.stop();
    }
  });

  test("rejects ID token signed with wrong key", async () => {
    _resetCachesForTests();
    globalThis.fetch = savedFetch;
    const idp = await startFakeIdp({ clientId: "test-client", clientSecret: "test-secret" });
    try {
      idp.useWrongKeyForNext(true);
      idp.setNextNonce("n-3");
      await expect(
        exchangeAndVerify({
          config: {
            issuer: idp.url,
            client_id: "test-client",
            client_secret: "test-secret",
            redirect_uri: "http://gatehouse.test/v1/auth/sso/callback",
            scopes: "openid profile email",
          },
          callbackParams: new URLSearchParams({ code: "test-code" }),
          codeVerifier: "v".repeat(43),
          expectedNonce: "n-3",
        })
      ).rejects.toThrow();
    } finally {
      await idp.stop();
    }
  });

  test("rejects ID token with mismatched nonce", async () => {
    _resetCachesForTests();
    globalThis.fetch = savedFetch;
    const idp = await startFakeIdp({ clientId: "test-client", clientSecret: "test-secret" });
    try {
      idp.setNextNonce("a-different-nonce");
      await expect(
        exchangeAndVerify({
          config: {
            issuer: idp.url,
            client_id: "test-client",
            client_secret: "test-secret",
            redirect_uri: "http://gatehouse.test/v1/auth/sso/callback",
            scopes: "openid profile email",
          },
          callbackParams: new URLSearchParams({ code: "test-code" }),
          codeVerifier: "v".repeat(43),
          expectedNonce: "expected-nonce",
        })
      ).rejects.toThrow();
    } finally {
      await idp.stop();
    }
  });

  test("rejects userinfo whose sub does not match ID token", async () => {
    _resetCachesForTests();
    globalThis.fetch = savedFetch;
    const idp = await startFakeIdp({ clientId: "test-client", clientSecret: "test-secret" });
    try {
      idp.setNextUser({ sub: "real-sub", email: "x@example.com", email_verified: true });
      idp.setNextNonce("n-mismatch");
      idp.setNextUserinfoSubOverride("different-sub");
      const cfg = {
        issuer: idp.url,
        client_id: "test-client",
        client_secret: "test-secret",
        redirect_uri: "http://gatehouse.test/v1/auth/sso/callback",
        scopes: "openid profile email",
      };
      const result = await exchangeAndVerify({
        config: cfg,
        callbackParams: new URLSearchParams({ code: "test-code" }),
        codeVerifier: "v".repeat(43),
        expectedNonce: "n-mismatch",
      });
      await expect(
        fetchUserinfo({
          config: cfg,
          accessToken: result.accessToken,
          expectedSubject: result.claims.sub as string,
        })
      ).rejects.toThrow();
    } finally {
      await idp.stop();
    }
  });
});
