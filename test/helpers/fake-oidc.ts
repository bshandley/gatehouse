import { Hono } from "hono";
import { SignJWT, exportJWK, generateKeyPair } from "jose";

export interface FakeIdpUser {
  sub: string;
  email?: string;
  email_verified?: boolean;
}

export interface FakeIdpServer {
  url: string;
  /** Set the user that the next /token + /userinfo round trip will return. */
  setNextUser(user: FakeIdpUser): void;
  /** Override the kid the next ID token is signed with. Default: matches /jwks. */
  setNextSigningKid(kid: string | null): void;
  /** Override the audience the next ID token is signed for. Default: matches client. */
  setNextAud(aud: string | null): void;
  /** Override the issuer the next ID token claims. Default: matches /.well-known. */
  setNextIss(iss: string | null): void;
  /** Replace the signing key for the next ID token (simulates a JWKS-mismatch attack). */
  useWrongKeyForNext(use: boolean): void;
  /** Set the nonce that the next ID token will carry. Default: echo what the test asks for. */
  setNextNonce(nonce: string | null): void;
  /** Make /token return an HTTP 4xx for the next call. */
  failNextTokenExchange(status: number): void;
  /** Issue a code that /token will accept. Default: "test-code". */
  setExpectedCode(code: string): void;
  /**
   * Override the sub returned by /userinfo for the next call only.
   * When non-null, /userinfo will return this sub instead of nextUser.sub.
   * Resets to null after one use (one-shot).
   */
  setNextUserinfoSubOverride(sub: string | null): void;
  /**
   * If true, discovery declares `authorization_response_iss_parameter_supported`
   * (RFC 9207). Real-world IdPs that set this include PocketID, recent Keycloak,
   * Authelia. When set, oauth4webapi requires `iss` in the callback params.
   */
  setIssParameterSupported(supported: boolean): void;
  /** Stop the server. */
  stop(): Promise<void>;
}

export async function startFakeIdp(opts: { clientId: string; clientSecret: string }): Promise<FakeIdpServer> {
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const wrongKeyPair = await generateKeyPair("RS256", { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid: "test-kid", alg: "RS256", use: "sig" };

  let nextUser: FakeIdpUser = { sub: "fake-sub", email: "alice@example.com", email_verified: true };
  let nextNonce: string | null = null;
  let nextAud: string | null = null;
  let nextIss: string | null = null;
  let nextKid: string | null = "test-kid";
  let useWrongKey = false;
  let expectedCode = "test-code";
  let failTokenStatus: number | null = null;
  let nextUserinfoSubOverride: string | null = null;
  let issParameterSupported = false;

  const codeToNonce = new Map<string, string>(); // code -> nonce that started this flow

  const app = new Hono();

  app.get("/.well-known/openid-configuration", (c) => {
    const base = baseUrl();
    const meta: Record<string, unknown> = {
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      jwks_uri: `${base}/jwks`,
      userinfo_endpoint: `${base}/userinfo`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
    };
    if (issParameterSupported) {
      meta.authorization_response_iss_parameter_supported = true;
    }
    return c.json(meta);
  });

  app.get("/jwks", (c) => c.json({ keys: [jwk] }));

  app.get("/authorize", (c) => {
    // The test calls /v1/auth/sso/callback directly with a fixed code; we don't need to redirect.
    // Return 200 so any direct probe doesn't error. Real flow won't hit this path during tests.
    const nonce = c.req.query("nonce");
    if (nonce) codeToNonce.set(expectedCode, nonce);
    return c.text("fake-authorize-ok", 200);
  });

  app.post("/token", async (c) => {
    if (failTokenStatus !== null) {
      const status = failTokenStatus;
      failTokenStatus = null;
      return c.json({ error: "invalid_grant" }, status as any);
    }

    const body = await c.req.parseBody();
    if (body.code !== expectedCode) {
      return c.json({ error: "invalid_grant" }, 400);
    }

    const aud = nextAud ?? opts.clientId;
    const iss = nextIss ?? baseUrl();
    const nonceClaim = nextNonce ?? codeToNonce.get(expectedCode) ?? "";
    const signKey = useWrongKey ? wrongKeyPair.privateKey : privateKey;
    const kid = nextKid ?? "test-kid";

    // "Next-*" overrides are one-shot; reset to defaults after consuming.
    nextAud = null;
    nextIss = null;
    nextNonce = null;
    nextKid = "test-kid";
    useWrongKey = false;

    const idToken = await new SignJWT({
      sub: nextUser.sub,
      email: nextUser.email,
      email_verified: nextUser.email_verified,
      nonce: nonceClaim,
    })
      .setProtectedHeader({ alg: "RS256", kid, typ: "JWT" })
      .setIssuer(iss)
      .setAudience(aud)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(signKey);

    return c.json({
      access_token: "fake-access-token-" + nextUser.sub,
      id_token: idToken,
      token_type: "Bearer",
      expires_in: 300,
    });
  });

  app.get("/userinfo", (c) => {
    const auth = c.req.header("Authorization") || "";
    if (!auth.startsWith("Bearer fake-access-token-")) {
      return c.json({ error: "invalid_token" }, 401);
    }
    const subOverride = nextUserinfoSubOverride;
    nextUserinfoSubOverride = null; // one-shot: reset after use
    return c.json({
      sub: subOverride ?? nextUser.sub,
      email: nextUser.email,
      email_verified: nextUser.email_verified,
    });
  });

  const server = Bun.serve({ port: 0, fetch: app.fetch });
  const port = server.port;
  const baseUrl = () => `http://localhost:${port}`;

  return {
    url: baseUrl(),
    setNextUser(u) { nextUser = u; },
    setNextSigningKid(kid) { nextKid = kid; },
    setNextAud(aud) { nextAud = aud; },
    setNextIss(iss) { nextIss = iss; },
    useWrongKeyForNext(use) { useWrongKey = use; },
    setNextNonce(n) { nextNonce = n; },
    failNextTokenExchange(status) { failTokenStatus = status; },
    setExpectedCode(code) { expectedCode = code; },
    setNextUserinfoSubOverride(sub) { nextUserinfoSubOverride = sub; },
    setIssParameterSupported(supported) {
      issParameterSupported = supported;
      // Discovery is cached on the client side; tests that flip this between
      // calls need to call _resetCachesForTests() in src/auth/oidc.ts.
    },
    stop: async () => { await server.stop(); },
  };
}
