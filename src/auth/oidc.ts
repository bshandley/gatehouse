import * as oauth from "oauth4webapi";

export interface OidcConfig {
  issuer: string;
  client_id: string;
  client_secret: string;
  redirect_uri: string;
  scopes: string;
}

interface DiscoveryCacheEntry {
  metadata: oauth.AuthorizationServer;
  expiresAt: number;
}

const DISCOVERY_TTL_MS = 60 * 60 * 1000;
const discoveryCache = new Map<string, DiscoveryCacheEntry>();

/** Test-only: clear all caches. */
export function _resetCachesForTests() {
  discoveryCache.clear();
}

/**
 * Returns options with allowInsecureRequests set ONLY for HTTP loopback issuers.
 * This exists for the in-process fake IdP used in tests. Any non-loopback HTTP
 * issuer falls through to oauth4webapi's default HTTPS enforcement (it will throw).
 */
function httpOpts(issuerUrl: URL): Record<symbol, boolean> | undefined {
  if (issuerUrl.protocol !== "http:") return undefined;
  const host = issuerUrl.hostname;
  if (host === "localhost" || host === "127.0.0.1" || host === "::1") {
    return { [oauth.allowInsecureRequests]: true };
  }
  return undefined;
}

/**
 * Fetch and cache the OIDC discovery document for an issuer.
 * TTL: 1 hour.
 */
export async function getDiscovery(issuer: string): Promise<oauth.AuthorizationServer> {
  const issuerUrl = new URL(issuer);
  const cacheKey = issuerUrl.href;
  const now = Date.now();
  const cached = discoveryCache.get(cacheKey);
  if (cached && cached.expiresAt > now) {
    return cached.metadata;
  }
  const opts = httpOpts(issuerUrl);
  const response = await oauth.discoveryRequest(issuerUrl, { algorithm: "oidc", ...opts });
  const metadata = await oauth.processDiscoveryResponse(issuerUrl, response);
  discoveryCache.set(cacheKey, { metadata, expiresAt: now + DISCOVERY_TTL_MS });
  return metadata;
}

export interface LoginParams {
  state: string;
  nonce: string;
  codeVerifier: string;
}

/** Generate fresh state, nonce, and PKCE code verifier for one login attempt. */
export async function generateLoginParams(): Promise<LoginParams> {
  return {
    state: oauth.generateRandomState(),
    nonce: oauth.generateRandomNonce(),
    codeVerifier: oauth.generateRandomCodeVerifier(),
  };
}

export interface BuildAuthUrlInput {
  config: OidcConfig;
  state: string;
  nonce: string;
  codeVerifier: string;
}

export interface ExchangeAndVerifyInput {
  config: OidcConfig;
  /**
   * The full set of query params the IdP redirected back with. Must include
   * `code`, and (if the AS sets `authorization_response_iss_parameter_supported`,
   * per RFC 9207) must also include `iss`. Pass the request URL's searchParams
   * directly so we don't drop fields the AS expects to validate.
   */
  callbackParams: URLSearchParams;
  codeVerifier: string;
  expectedNonce: string;
}

export interface ExchangeAndVerifyResult {
  accessToken: string;
  claims: oauth.IDToken;
}

/**
 * Exchange the authorization code for tokens and verify the ID token.
 * oauth4webapi.processAuthorizationCodeResponse performs:
 *   - signature verification against jwks_uri
 *   - iss / aud / exp checks
 *   - nonce match against expectedNonce
 * It throws on any failure.
 */
export async function exchangeAndVerify(input: ExchangeAndVerifyInput): Promise<ExchangeAndVerifyResult> {
  const issuerUrl = new URL(input.config.issuer);
  const opts = httpOpts(issuerUrl);
  const meta = await getDiscovery(input.config.issuer);
  const client: oauth.Client = { client_id: input.config.client_id };
  const clientAuth = oauth.ClientSecretPost(input.config.client_secret);

  // validateAuthResponse enforces RFC 9207 `iss` when the AS declares it
  // supported in discovery. Pass the full request searchParams through so
  // that param is available; we use skipStateCheck because state is validated
  // separately via the sso_login_state row consumption.
  const validatedParams = oauth.validateAuthResponse(meta, client, input.callbackParams, oauth.skipStateCheck);

  const tokenResponse = await oauth.authorizationCodeGrantRequest(
    meta,
    client,
    clientAuth,
    validatedParams,
    input.config.redirect_uri,
    input.codeVerifier,
    opts
  );

  const tokens = await oauth.processAuthorizationCodeResponse(meta, client, tokenResponse, {
    expectedNonce: input.expectedNonce,
    requireIdToken: true,
    ...opts,
  });

  if (!tokens.access_token || !tokens.id_token) {
    throw new Error("token response missing access_token or id_token");
  }

  // Explicitly verify the ID token signature against the issuer's JWKS.
  // oauth4webapi v3 separates structural validation from signature verification;
  // validateApplicationLevelSignature fetches /jwks and checks the signature.
  await oauth.validateApplicationLevelSignature(meta, tokenResponse, opts);

  const claims = oauth.getValidatedIdTokenClaims(tokens) as oauth.IDToken;
  return { accessToken: tokens.access_token, claims };
}

export interface FetchUserinfoInput {
  config: OidcConfig;
  accessToken: string;
  expectedSubject: string;
}

/** Fetch userinfo using the access token. Returns the claims map.
 *
 * Uses processUserInfoResponse to verify that the userinfo `sub` matches
 * the expected subject from the ID token. Per OIDC Core 5.3.2, a mismatch
 * must be rejected to prevent a buggy or malicious IdP from linking the
 * wrong user.
 */
export async function fetchUserinfo(input: FetchUserinfoInput): Promise<Record<string, unknown>> {
  const issuerUrl = new URL(input.config.issuer);
  const opts = httpOpts(issuerUrl);
  const meta = await getDiscovery(input.config.issuer);
  const client: oauth.Client = { client_id: input.config.client_id };
  const response = await oauth.userInfoRequest(meta, client, input.accessToken, opts);
  // processUserInfoResponse verifies the userinfo `sub` matches the expected
  // subject (from the ID token). Per OIDC Core 5.3.2, mismatch must reject.
  return await oauth.processUserInfoResponse(meta, client, input.expectedSubject, response, opts) as Record<string, unknown>;
}

/** Build the IdP authorization URL with PKCE S256. */
export async function buildAuthUrl(input: BuildAuthUrlInput): Promise<URL> {
  const meta = await getDiscovery(input.config.issuer);
  if (!meta.authorization_endpoint) {
    throw new Error("issuer missing authorization_endpoint");
  }
  const codeChallenge = await oauth.calculatePKCECodeChallenge(input.codeVerifier);
  const url = new URL(meta.authorization_endpoint);
  url.searchParams.set("client_id", input.config.client_id);
  url.searchParams.set("redirect_uri", input.config.redirect_uri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", input.config.scopes);
  url.searchParams.set("state", input.state);
  url.searchParams.set("nonce", input.nonce);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url;
}
