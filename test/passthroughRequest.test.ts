import { describe, expect, test } from "bun:test";
import { resolveAutoInject } from "../src/api/proxy";
import {
  joinUpstreamUrl,
  extractCallerCredentials,
  resolvePassthroughInject,
  buildUpstreamHeaders,
  buildResponseHeaders,
  rewriteLocation,
  PassthroughInjectError,
  isForbiddenInjectHeader,
} from "../src/proxy/passthroughRequest";

const UP = "https://api.example.com";
const UPV = "https://api.example.com/v1";

function join(rest: string, q = "", up = UP) {
  const r = joinUpstreamUrl(up, rest, q);
  return r.ok ? r.url : null;
}

describe("joinUpstreamUrl", () => {
  test("empty remainder yields upstream_url", () => {
    expect(join("")).toBe(UP + "/");
    expect(join("", "", UPV)).toBe(UPV);
  });
  test("slash remainder", () => {
    expect(join("/")).toBe(UP + "/");
    expect(join("/", "", UPV)).toBe(UPV + "/");
  });
  test("joins under a path prefix and keeps query byte for byte", () => {
    expect(join("/users/1", "?a=1&b=%2e%2e&c=%2F&d=a b".replace(" ", "+"), UPV)).toBe(
      UPV + "/users/1?a=1&b=%2e%2e&c=%2F&d=a+b"
    );
    expect(join("", "?x=1", UPV)).toBe(UPV + "?x=1");
  });
  test("host-like remainders never change the origin", () => {
    for (const rest of ["//other.example.com/x", "/@other.example.com", "/a//b"]) {
      const u = join(rest);
      expect(u).not.toBeNull();
      expect(new URL(u!).host).toBe("api.example.com");
    }
    expect(join("//other.example.com/x", "", UPV)).toBe(UPV + "//other.example.com/x");
  });
  test("rejects backslashes, raw or encoded", () => {
    expect(join("/\\other.example.com")).toBeNull();
    expect(join("/a%5Cb")).toBeNull();
    expect(join("/a%5cb")).toBeNull();
  });
  test("rejects encoded slash in any case", () => {
    expect(join("/a%2fb")).toBeNull();
    expect(join("/a%2Fb")).toBeNull();
    expect(join("/..%2f..")).toBeNull();
  });
  test("rejects dot segments, raw and encoded", () => {
    for (const rest of ["/.", "/..", "/a/./b", "/a/../b", "/a/%2e%2e/b", "/%2E%2E", "/%2e", "/a/%2E/b", "/.%2e", "/%2e./x"]) {
      expect(join(rest)).toBeNull();
      expect(join(rest, "", UPV)).toBeNull();
    }
  });
  test("double encoding and path parameters are rejected", () => {
    for (const rest of ["/%252e%252e/x", "/%252e%252e", "/a%252fb", "/a%255cb", "/a%252Fb", "/a%255Cb", "/..;/x", "/.;/x", "/%2e%2e;x", "/..;a=b/x", "/a/..;/x"]) {
      expect(join(rest, "", UPV)).toBeNull();
      expect(join(rest)).toBeNull();
    }
  });
  test("legitimate remainders still pass", () => {
    for (const rest of ["/a;b=c/d", "/files/report%20final.pdf", "/a%25b", "/v2/items/100%25", "/users/a.b/c..d", "/.well-known/x", "/..a", "/a.."]) {
      const r = joinUpstreamUrl(UPV, rest, "");
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.url).toBe(UPV + rest);
    }
  });
  test("result is the canonical href", () => {
    const r = joinUpstreamUrl(UPV, "/a b".replace(" ", "%20"), "?q=1");
    expect(r).toEqual({ ok: true, url: new URL(UPV + "/a%20b?q=1").href });
  });
  test("base with and without trailing slash join identically", () => {
    for (const rest of ["", "/", "/x", "/x/y"]) {
      expect(joinUpstreamUrl("https://api.example.com/v1/", rest, "?a=1")).toEqual(joinUpstreamUrl(UPV, rest, "?a=1"));
    }
    expect(joinUpstreamUrl("https://api.example.com/v1//", "/x", "")).toEqual(joinUpstreamUrl(UPV, "/x", ""));
  });
  test("query is preserved for an ASCII query", () => {
    const q = "?a=1&b=%2e%2e&c=%2F&d=x+y&e=%252e&f=/..//&g=@h:80&h=;x";
    const r = joinUpstreamUrl(UPV, "/p", q);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(new URL(r.url).search).toBe(q);
      expect(new URL(r.url).pathname).toBe("/v1/p");
    }
  });
  test("IPv6 upstream", () => {
    const up = "http://[::1]:8080/base";
    expect(joinUpstreamUrl(up, "/x", "?a=1")).toEqual({ ok: true, url: "http://[::1]:8080/base/x?a=1" });
    expect(joinUpstreamUrl(up, "//[::2]/x", "")).toEqual({ ok: true, url: "http://[::1]:8080/base//[::2]/x" });
    expect(joinUpstreamUrl(up, "/../x", "")).toEqual({ ok: false });
  });
  test("dots inside longer segments are fine", () => {
    expect(join("/a.b/..c/d..")).toBe(UP + "/a.b/..c/d..");
  });
  test("rejects control characters, raw or encoded, tab, newline", () => {
    for (const rest of ["/a\u0000b", "/a%00b", "/a%0ab", "/a%0Db", "/a\tb", "/a\nb", "/a\rb", "/a%09b", "/a\u007fb", "/a%7fb", "/a b"]) {
      expect(join(rest)).toBeNull();
    }
    expect(join("/a", "?x=\u0000")).toBeNull();
    expect(join("/a", "?x=\ny")).toBeNull();
    expect(join("/a", "?x=\ty")).toBeNull();
  });
  test("rejects # and ? in the path part, allows them encoded", () => {
    expect(join("/a#b")).toBeNull();
    expect(join("/a?b")).toBeNull();
    expect(join("/a%23b%3Fc")).toBe(UP + "/a%23b%3Fc");
  });
  test("query cannot carry a fragment or alter path or origin", () => {
    expect(join("/a", "?x=1#frag")).toBeNull();
    const u = join("/a", "?next=//evil.example.com/&u=@evil.example.com", UPV);
    expect(new URL(u!).origin).toBe(UP);
    expect(new URL(u!).pathname).toBe("/v1/a");
  });
  test("empty query is fine, query must start with ?", () => {
    expect(join("/a", "")).toBe(UP + "/a");
    expect(join("/a", "x=1")).toBeNull();
  });
  test("rejects very long remainder, accepts moderately long", () => {
    expect(join("/" + "a".repeat(9000))).toBeNull();
    expect(join("/" + "a".repeat(1000))).toBe(UP + "/" + "a".repeat(1000));
  });
  test("rejects invalid percent-encoding", () => {
    expect(join("/%zz")).toBeNull();
    expect(join("/%")).toBeNull();
    expect(join("/a%2")).toBeNull();
    expect(join("/%ff")).toBeNull();
  });
  test("remainder must start with a slash", () => {
    expect(join("a")).toBeNull();
    expect(join("@other.example.com")).toBeNull();
    expect(join(".example.com")).toBeNull();
  });
  test("trailing slash on upstream path is trimmed", () => {
    expect(join("/x", "", "https://api.example.com/v1/")).toBe(UPV + "/x");
  });
  test("unparseable upstream fails", () => {
    expect(joinUpstreamUrl("not a url", "/x", "")).toEqual({ ok: false });
  });
  test("stays under the prefix and origin for hostile input", () => {
    for (const rest of ["//x", "/v1/../x", "/%2e%2e/%2e%2e", "/@x", "/:80", "/x:y@z"]) {
      const r = joinUpstreamUrl(UPV, rest, "");
      if (r.ok) {
        const u = new URL(r.url);
        expect(u.origin).toBe(UP);
        expect(u.pathname.startsWith("/v1/") || u.pathname === "/v1").toBe(true);
      }
    }
  });
});

describe("extractCallerCredentials", () => {
  const meta = (m: Record<string, string>) => ({ metadata: m });
  const H = (o: Record<string, string>) => new Headers(o);

  test("no headers", () => {
    expect(extractCallerCredentials(H({}), null)).toEqual([]);
    expect(extractCallerCredentials(H({}), meta({}))).toEqual([]);
  });
  test("injection header with default Authorization strips Bearer", () => {
    expect(extractCallerCredentials(H({ Authorization: "Bearer tok1" }), meta({}))).toEqual(["tok1"]);
  });
  test("bare token and extra spaces and case-insensitive scheme", () => {
    expect(extractCallerCredentials(H({ authorization: "tok1" }), meta({}))).toEqual(["tok1"]);
    expect(extractCallerCredentials(H({ authorization: "  bEaReR    tok1  " }), meta({}))).toEqual(["tok1"]);
  });
  test("custom injection header", () => {
    expect(extractCallerCredentials(H({ "X-Custom": "tok2" }), meta({ header_name: "x-custom", auth_scheme: "" }))).toEqual(["tok2"]);
    expect(extractCallerCredentials(H({ "X-Custom": "Key tok2" }), meta({ header_name: "X-Custom", auth_scheme: "Key" }))).toEqual(["tok2"]);
  });
  test("Basic yields the password after the first colon", () => {
    const b = btoa("user:pa:ss");
    expect(extractCallerCredentials(H({ Authorization: `Basic ${b}` }), meta({ auth_scheme: "Basic" }))).toEqual(["pa:ss"]);
    expect(extractCallerCredentials(H({ Authorization: `basic   ${b}` }), meta({}))).toEqual(["pa:ss"]);
  });
  test("malformed Basic yields nothing and does not throw", () => {
    expect(extractCallerCredentials(H({ Authorization: "Basic !!!notbase64" }), meta({}))).toEqual([]);
    expect(extractCallerCredentials(H({ Authorization: `Basic ${btoa("nocolon")}` }), meta({}))).toEqual([]);
    expect(extractCallerCredentials(H({ Authorization: `Basic ${btoa("user:")}` }), meta({}))).toEqual([]);
    expect(extractCallerCredentials(H({ Authorization: "Basic " }), meta({}))).toEqual([]);
  });
  test("Authorization Bearer then x-api-key when meta is null", () => {
    expect(extractCallerCredentials(H({ Authorization: "Bearer a", "X-API-Key": "b" }), null)).toEqual(["a", "b"]);
    expect(extractCallerCredentials(H({ "x-api-key": "b" }), null)).toEqual(["b"]);
  });
  test("meta null ignores Basic and non-Bearer Authorization", () => {
    expect(extractCallerCredentials(H({ Authorization: `Basic ${btoa("u:p")}` }), null)).toEqual([]);
  });
  test("spec order with the injection header first", () => {
    const r = extractCallerCredentials(
      H({ "x-api-key": "c", Authorization: "Bearer b", "X-Token": "a" }),
      meta({ header_name: "X-Token", auth_scheme: "" })
    );
    expect(r).toEqual(["a", "b", "c"]);
  });
  test("de-duplicates and never returns empty strings", () => {
    expect(extractCallerCredentials(H({ Authorization: "Bearer a", "x-api-key": "a" }), meta({}))).toEqual(["a"]);
    expect(extractCallerCredentials(H({ Authorization: "Bearer", "x-api-key": "   " }), meta({}))).toEqual([]);
    expect(extractCallerCredentials(H({ "x-api-key": "" }), meta({}))).toEqual([]);
    for (const c of extractCallerCredentials(H({ Authorization: "Bearer  ", "x-api-key": " " }), meta({}))) {
      expect(c).not.toBe("");
    }
  });
});

describe("resolvePassthroughInject", () => {
  const table: Array<[string, Record<string, string> | undefined]> = [
    ["sekret-value", undefined],
    ["sekret-value", {}],
    ["sekret-value", { header_name: "x-api-key" }],
    ["sekret-value", { header_name: "x-api-key", auth_scheme: "" }],
    ["sekret-value", { auth_scheme: "Token" }],
    ["sekret-value", { auth_scheme: "" }],
    ["Bearer already", {}],
    ["Basic already", { auth_scheme: "Basic" }],
    ["user:pass", { auth_scheme: "Bearer" }],
    ["user:pass", { header_name: "X-A", auth_scheme: "Digest" }],
  ];
  test("equals resolveAutoInject everywhere except schemeless Basic", () => {
    for (const [v, m] of table) {
      const meta = m ? { metadata: m } : {};
      expect(resolvePassthroughInject(v, meta)).toEqual(resolveAutoInject(v, meta));
    }
    expect(resolvePassthroughInject("v", null)).toEqual(resolveAutoInject("v", null));
  });
  test("Basic with a schemeless value is base64-encoded", () => {
    expect(resolvePassthroughInject("user:pass", { metadata: { auth_scheme: "Basic" } })).toEqual({
      headerName: "Authorization",
      headerValue: "Basic " + btoa("user:pass"),
    });
    expect(resolvePassthroughInject("user:pass", { metadata: { auth_scheme: "basic", header_name: "X-A" } }).headerValue).toBe(
      "basic " + btoa("user:pass")
    );
  });
});

describe("extractCallerCredentials with an invalid header_name", () => {
  test("skips that location instead of throwing", () => {
    const h = new Headers({ Authorization: "Bearer tok-a", "x-api-key": "tok-b" });
    expect(extractCallerCredentials(h, { metadata: { header_name: "bad header" } })).toEqual(["tok-a", "tok-b"]);
  });
});

describe("buildUpstreamHeaders", () => {
  const meta = { metadata: {} as Record<string, string> };
  test("strips Gatehouse credentials, hop-by-hop, host, forwarding, keeps cookies", () => {
    const h = new Headers({
      Authorization: "Bearer gh-token",
      "X-API-Key": "gh-key",
      Host: "gatehouse.local",
      "Content-Length": "5",
      "X-Forwarded-For": "1.2.3.4",
      "x-forwarded-proto": "https",
      "X-Real-IP": "1.2.3.4",
      Forwarded: "for=1.2.3.4",
      Via: "1.1 proxy",
      Connection: "keep-alive, X-Hop",
      "X-Hop": "1",
      "Keep-Alive": "timeout=5",
      TE: "trailers",
      Upgrade: "websocket",
      "Transfer-Encoding": "chunked",
      Trailer: "x",
      "Proxy-Authorization": "Basic zzz",
      Cookie: "a=b",
      Accept: "application/json",
      "X-Custom": "keep",
    });
    const out = buildUpstreamHeaders(h, meta, "real-secret");
    expect([...out.keys()].sort()).toEqual(["accept", "authorization", "cookie", "x-custom"]);
    expect(out.get("authorization")).toBe("Bearer real-secret");
    expect(out.get("cookie")).toBe("a=b");
  });
  test("injection header x-api-key: caller Authorization never present", () => {
    const out = buildUpstreamHeaders(
      new Headers({ Authorization: "Bearer gh", "x-api-key": "gh2" }),
      { metadata: { header_name: "x-api-key", auth_scheme: "" } },
      "real"
    );
    expect(out.get("authorization")).toBeNull();
    expect(out.get("x-api-key")).toBe("real");
  });
  test("injection header Authorization: caller x-api-key never present", () => {
    const out = buildUpstreamHeaders(new Headers({ "x-api-key": "gh2", Authorization: "Bearer gh" }), meta, "real");
    expect(out.get("x-api-key")).toBeNull();
    expect(out.get("authorization")).toBe("Bearer real");
  });
  test("custom injection header is stripped case-insensitively with exactly one value", () => {
    const h = new Headers();
    h.append("X-Token", "caller1");
    h.append("x-token", "caller2");
    const out = buildUpstreamHeaders(h, { metadata: { header_name: "x-TOKEN", auth_scheme: "" } }, "real");
    expect(out.get("x-token")).toBe("real");
    expect([...out.entries()].filter(([k]) => k === "x-token").length).toBe(1);
  });
  test("credential header named in Connection in odd case is stripped", () => {
    const out = buildUpstreamHeaders(
      new Headers({ Connection: "close, AUTHORIZATION , x-api-KEY", Authorization: "Bearer gh", "X-Api-Key": "k", Accept: "*/*" }),
      { metadata: { header_name: "x-other", auth_scheme: "" } },
      "real"
    );
    expect(out.get("authorization")).toBeNull();
    expect(out.get("x-api-key")).toBeNull();
    expect(out.get("x-other")).toBe("real");
    expect(out.get("accept")).toBe("*/*");
  });
  test("duplicate headers survive combined", () => {
    const h = new Headers();
    h.append("Accept", "a");
    h.append("accept", "b");
    expect(buildUpstreamHeaders(h, meta, "s").get("accept")).toBe("a, b");
  });
  test("Basic injection encodes a schemeless value", () => {
    const out = buildUpstreamHeaders(new Headers(), { metadata: { auth_scheme: "Basic" } }, "u:p");
    expect(out.get("authorization")).toBe("Basic " + btoa("u:p"));
  });
  test("does not mutate its input", () => {
    const h = new Headers({ Authorization: "Bearer gh" });
    buildUpstreamHeaders(h, meta, "s");
    expect(h.get("authorization")).toBe("Bearer gh");
  });
  test("strips Range and If-Range in any case, so the upstream answers with the whole body", () => {
    const out = buildUpstreamHeaders(
      new Headers({ RANGE: "bytes=0-3", "if-RANGE": '"etag"', Accept: "*/*" }),
      meta,
      "s"
    );
    expect(out.get("range")).toBeNull();
    expect(out.get("if-range")).toBeNull();
    expect(out.get("accept")).toBe("*/*");
  });
  test("strips Expect in any case: Gatehouse has already read the whole body", () => {
    const out = buildUpstreamHeaders(new Headers({ EXPECT: "100-continue", Accept: "*/*" }), meta, "s");
    expect(out.get("expect")).toBeNull();
    expect(out.get("accept")).toBe("*/*");
  });
  test("strips Accept-Encoding, so only encodings the fetch can decode are asked for", () => {
    const out = buildUpstreamHeaders(new Headers({ "Accept-Encoding": "compress" }), meta, "s");
    expect(out.get("accept-encoding")).toBeNull();
  });
});

describe("buildResponseHeaders", () => {
  test("strips hop-by-hop, length, encoding, gatehouse error, Connection-named", () => {
    const { headers } = buildResponseHeaders(
      new Headers({
        Connection: "X-Drop",
        "X-Drop": "1",
        "Keep-Alive": "x",
        "Transfer-Encoding": "chunked",
        "Content-Length": "9",
        "Content-Encoding": "gzip",
        "X-Gatehouse-Error": "spoofed",
        "Content-Type": "text/plain",
        "X-Keep": "ok",
      }),
      []
    );
    expect([...headers.keys()].sort()).toEqual(["content-type", "x-keep"]);
  });
  test("preserves multiple Set-Cookie", () => {
    const up = new Headers();
    up.append("Set-Cookie", "a=1; Path=/");
    up.append("Set-Cookie", "b=2; Path=/");
    const { headers } = buildResponseHeaders(up, []);
    expect(headers.getSetCookie()).toEqual(["a=1; Path=/", "b=2; Path=/"]);
  });
  test("redacts and counts secrets in headers and cookies", () => {
    const up = new Headers({ "X-Echo": "token=supersecret1 and supersecret1" });
    up.append("Set-Cookie", "s=supersecret1");
    const { headers, redactions } = buildResponseHeaders(up, ["supersecret1"]);
    expect(headers.get("x-echo")).toBe("token=[REDACTED] and [REDACTED]");
    expect(headers.getSetCookie()).toEqual(["s=[REDACTED]"]);
    expect(redactions).toBe(3);
  });
});

describe("rewriteLocation", () => {
  const reqUrl = "https://api.example.com/v1/things/1";
  const base = "https://gh.example.net";
  const rw = (loc: string, up = UPV, req = reqUrl) => rewriteLocation(loc, req, up, "myalias", base);

  test("absolute same-origin under prefix", () => {
    expect(rw("https://api.example.com/v1/things/2?x=1")).toEqual({ ok: true, location: base + "/p/myalias/things/2?x=1" });
  });
  test("absolute-path, relative and parent-relative", () => {
    expect(rw("/v1/other")).toEqual({ ok: true, location: base + "/p/myalias/other" });
    expect(rw("2")).toEqual({ ok: true, location: base + "/p/myalias/things/2" });
    expect(rw("../x")).toEqual({ ok: true, location: base + "/p/myalias/x" });
  });
  test("scheme-relative same host", () => {
    expect(rw("//api.example.com/v1/z")).toEqual({ ok: true, location: base + "/p/myalias/z" });
  });
  test("prefix itself maps to the alias root", () => {
    expect(rw("/v1")).toEqual({ ok: true, location: base + "/p/myalias" });
  });
  test("segment boundary and escapes above prefix are refused", () => {
    expect(rw("/v10/x")).toEqual({ ok: false });
    expect(rw("/other")).toEqual({ ok: false });
    expect(rw("../../x")).toEqual({ ok: false });
  });
  test("cross-origin refused", () => {
    expect(rw("https://evil.example.com/v1/x")).toEqual({ ok: false });
    expect(rw("//evil.example.com/v1/x")).toEqual({ ok: false });
    expect(rw("http://api.example.com/v1/x")).toEqual({ ok: false });
    expect(rw("https://api.example.com:8443/v1/x")).toEqual({ ok: false });
  });
  test("no prefix upstream accepts any path", () => {
    expect(rw("/a/b?q=1", UP, "https://api.example.com/a")).toEqual({ ok: true, location: base + "/p/myalias/a/b?q=1" });
  });
  test("garbage location is refused", () => {
    expect(rw("http://[bad")).toEqual({ ok: false });
  });
});

describe("injection errors and forbidden headers", () => {
  const secret = "s\u00e9cret\u4e2dvalue";
  const basic = { metadata: { auth_scheme: "Basic" } };
  test("non-Latin1 secret with Basic throws a typed error without the secret", () => {
    for (const fn of [
      () => resolvePassthroughInject(secret, basic),
      () => buildUpstreamHeaders(new Headers(), basic, secret),
    ]) {
      let err: unknown;
      try {
        fn();
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(PassthroughInjectError);
      expect((err as Error).message).not.toContain(secret);
      expect((err as Error).message).not.toContain("\u4e2d");
    }
  });
  test("Latin1 secret with Basic still works", () => {
    expect(resolvePassthroughInject("caf\u00e9:pw", basic).headerValue).toBe("Basic " + btoa("caf\u00e9:pw"));
  });
  test("isForbiddenInjectHeader", () => {
    for (const n of ["host", "Host", "CONNECTION", "keep-alive", "proxy-authenticate", "Proxy-Authorization", "te", "trailer", "transfer-encoding", "upgrade", "content-length", "forwarded", "via", "x-real-ip", "cookie", "Cookie", "X-Forwarded-For", "x-forwarded-host"]) {
      expect(isForbiddenInjectHeader(n)).toBe(true);
    }
    for (const n of ["authorization", "x-api-key", "x-token", "api-key", "x-forward"]) {
      expect(isForbiddenInjectHeader(n)).toBe(false);
    }
  });
  test("buildUpstreamHeaders throws for a forbidden injection header", () => {
    for (const header_name of ["Cookie", "host", "X-Forwarded-For", "Via"]) {
      expect(() => buildUpstreamHeaders(new Headers(), { metadata: { header_name, auth_scheme: "" } }, "s")).toThrow(PassthroughInjectError);
    }
  });
});

describe("Connection: Set-Cookie and rewrite extras", () => {
  test("upstream Connection naming Set-Cookie strips cookies", () => {
    const up = new Headers({ Connection: "Set-Cookie" });
    up.append("Set-Cookie", "a=1");
    up.append("Set-Cookie", "b=2");
    const { headers } = buildResponseHeaders(up, []);
    expect(headers.getSetCookie()).toEqual([]);
    expect(headers.get("set-cookie")).toBeNull();
  });
  test("IPv6 upstream rewrite", () => {
    const up = "http://[::1]:8080/base";
    expect(rewriteLocation("http://[::1]:8080/base/x?y=1", "http://[::1]:8080/base/a", up, "al", "https://gh.example.net")).toEqual({
      ok: true,
      location: "https://gh.example.net/p/al/x?y=1",
    });
    expect(rewriteLocation("http://[::2]:8080/base/x", "http://[::1]:8080/base/a", up, "al", "https://gh.example.net")).toEqual({ ok: false });
  });
  test("userinfo in Location is dropped", () => {
    const r = rewriteLocation("https://user:pw@api.example.com/v1/x", "https://api.example.com/v1/a", UPV, "al", "https://gh.example.net");
    expect(r).toEqual({ ok: true, location: "https://gh.example.net/p/al/x" });
    if (r.ok) expect(r.location).not.toContain("pw");
  });
});
