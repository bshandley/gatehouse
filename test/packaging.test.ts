import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import YAML from "yaml";
import { VERSION } from "../src/version";

const TEMPLATES = [
  "packaging/unraid/gatehouse.xml",
  "packaging/umbrel/umbrel-app.yml",
  "packaging/umbrel/docker-compose.yml",
  "packaging/casaos/docker-compose.yml",
  "packaging/coolify/docker-compose.yml",
  "packaging/truenas/docker-compose.yml",
];
const SINGLE = "Gatehouse is single-instance by design";
const read = (p: string) => readFileSync(p, "utf8");

// Small XML checker: quoted attribute values (may contain ">"), self-closing
// tags, comments, the XML declaration. Entities are left alone. Returns
// the list of start-tags seen, or throws on malformed input.
type Tag = { name: string; attrs: Record<string, string> };
function checkXml(text: string): Tag[] {
  const tags: Tag[] = [];
  const stack: string[] = [];
  let i = 0;
  while (i < text.length) {
    const lt = text.indexOf("<", i);
    if (lt === -1) break;
    if (text.startsWith("<!--", lt)) {
      const end = text.indexOf("-->", lt + 4);
      if (end === -1) throw new Error("unterminated comment");
      i = end + 3;
      continue;
    }
    if (text.startsWith("<?", lt)) {
      const end = text.indexOf("?>", lt + 2);
      if (end === -1) throw new Error("unterminated declaration");
      i = end + 2;
      continue;
    }
    let j = lt + 1;
    const closing = text[j] === "/";
    if (closing) j++;
    const nm = /^[A-Za-z_][\w.-]*/.exec(text.slice(j));
    if (!nm) throw new Error(`bad tag at ${lt}`);
    const name = nm[0];
    j += name.length;
    const attrs: Record<string, string> = {};
    let selfClose = false;
    for (;;) {
      while (/\s/.test(text[j] ?? "")) j++;
      if (j >= text.length) throw new Error("unterminated tag");
      if (text[j] === ">") { j++; break; }
      if (text.startsWith("/>", j)) { selfClose = true; j += 2; break; }
      const an = /^[A-Za-z_][\w.:-]*/.exec(text.slice(j));
      if (!an || closing) throw new Error(`bad attribute at ${j}`);
      j += an[0].length;
      while (/\s/.test(text[j] ?? "")) j++;
      if (text[j] !== "=") throw new Error(`attribute without value at ${j}`);
      j++;
      while (/\s/.test(text[j] ?? "")) j++;
      const q = text[j];
      if (q !== '"' && q !== "'") throw new Error(`unquoted attribute at ${j}`);
      const qe = text.indexOf(q, j + 1);
      if (qe === -1) throw new Error("unterminated attribute value");
      attrs[an[0]] = text.slice(j + 1, qe);
      j = qe + 1;
    }
    if (closing) {
      if (stack.pop() !== name) throw new Error(`mismatched </${name}>`);
    } else {
      tags.push({ name, attrs });
      if (!selfClose) stack.push(name);
    }
    i = j;
  }
  if (stack.length) throw new Error(`unclosed <${stack[stack.length - 1]}>`);
  if (tags.length === 0) throw new Error("no elements");
  return tags;
}
const hasXmllint = spawnSync("xmllint", ["--version"]).status === 0;

describe("catalog templates", () => {
  test.each(TEMPLATES)("%s exists and sets no master key or root token value", (p) => {
    const text = read(p);
    expect(text).not.toMatch(/GATEHOUSE_MASTER_KEY\s*[=:]\s*\S/);
    expect(text).not.toMatch(/GATEHOUSE_ROOT_TOKEN\s*[=:]\s*\S/);
    expect(text).not.toContain("changeme");
  });

  test.each(TEMPLATES.filter((p) => p.endsWith(".yml") && p.includes("compose")))("%s does not mention the key variables as env entries with a value", (p) => {
    const doc = YAML.parse(read(p));
    for (const svc of Object.values<any>(doc.services)) {
      const env = svc.environment ?? {};
      const entries: [string, string][] = Array.isArray(env)
        ? env.map((e: string) => [e.split("=")[0], e.includes("=") ? e.slice(e.indexOf("=") + 1) : ""])
        : Object.entries(env).map(([k, v]) => [k, String(v ?? "")]);
      for (const [k, v] of entries) {
        if (k === "GATEHOUSE_MASTER_KEY" || k === "GATEHOUSE_ROOT_TOKEN") expect(v).toBe("");
      }
    }
  });

  test.each(TEMPLATES.filter((p) => !p.endsWith("umbrel-app.yml")))("%s pins the image to VERSION", (p) => {
    expect(read(p)).toContain(`ghcr.io/bshandley/gatehouse:${VERSION}`);
  });

  test.each(TEMPLATES.filter((p) => p.endsWith(".yml")))("%s is valid YAML", (p) => {
    expect(() => YAML.parse(read(p))).not.toThrow();
  });

  test("the XML checker rejects an unbalanced tag and accepts > inside an attribute value", () => {
    expect(() => checkXml("<A><B></A>")).toThrow();
    expect(() => checkXml("<A><B/>")).toThrow();
    expect(() => checkXml('<A x="1>')).toThrow();
    expect(() => checkXml("<A x=1/>")).toThrow();
    expect(() => checkXml('<A><C d="a > b &amp; c"/><!-- <x> --></A>')).not.toThrow();
  });

  test("the Unraid template is well-formed XML", () => {
    const text = read("packaging/unraid/gatehouse.xml");
    expect(() => checkXml(text)).not.toThrow();
    if (hasXmllint) {
      const r = spawnSync("xmllint", ["--noout", "packaging/unraid/gatehouse.xml"]);
      expect(r.status).toBe(0);
    }
  });

  test("the Unraid template has a /data volume, port 3100, the optional variables, and complete Config elements", () => {
    const text = read("packaging/unraid/gatehouse.xml");
    const tags = checkXml(text);
    const configs = tags.filter((t) => t.name === "Config");
    expect(configs.length).toBeGreaterThan(0);
    for (const c of configs) {
      for (const a of ["Name", "Target", "Type"]) expect(c.attrs[a]).toBeTruthy();
    }
    expect(configs.some((c) => c.attrs.Target === "/data" && c.attrs.Type === "Path")).toBe(true);
    expect(configs.some((c) => c.attrs.Target === "3100" && c.attrs.Type === "Port")).toBe(true);
    for (const v of ["GATEHOUSE_PUBLIC_URL", "GATEHOUSE_TRUSTED_PROXIES", "GATEHOUSE_PROXY_ALLOW_PRIVATE", "GATEHOUSE_OAUTH_ISSUER"]) {
      expect(configs.some((c) => c.attrs.Target === v)).toBe(true);
    }
    expect(text).toContain(`ghcr.io/bshandley/gatehouse:${VERSION}`);
  });

  test("no Unraid Config targets the master key or root token", () => {
    const configs = checkXml(read("packaging/unraid/gatehouse.xml")).filter((t) => t.name === "Config");
    for (const c of configs) {
      expect(c.attrs.Target).not.toBe("GATEHOUSE_MASTER_KEY");
      expect(c.attrs.Target).not.toBe("GATEHOUSE_ROOT_TOKEN");
    }
  });

  test("the Unraid template runs the container as 99:100", () => {
    const tags = checkXml(read("packaging/unraid/gatehouse.xml"));
    expect(read("packaging/unraid/gatehouse.xml")).toMatch(/<ExtraParams>[^<]*--user 99:100[^<]*<\/ExtraParams>/);
    expect(tags.some((t) => t.name === "ExtraParams")).toBe(true);
  });

  test("Umbrel runs the service as 1000:1000 and disables Umbrel proxy auth", () => {
    const doc = YAML.parse(read("packaging/umbrel/docker-compose.yml"));
    expect(doc.services.server.user).toBe("1000:1000");
    expect(doc.services.app_proxy.environment.PROXY_AUTH_ADD).toBe("false");
    expect(doc.services.app_proxy.environment.APP_HOST).toBe("gatehouse_server_1");
    expect(String(doc.services.app_proxy.environment.APP_PORT)).toBe("3100");
  });

  test("CasaOS runs the service as 1000:1000", () => {
    const doc = YAML.parse(read("packaging/casaos/docker-compose.yml"));
    expect(doc.services.gatehouse.user).toBe("1000:1000");
  });

  test("Coolify uses a named volume declared under top-level volumes", () => {
    const doc = YAML.parse(read("packaging/coolify/docker-compose.yml"));
    const mount = (doc.services.gatehouse.volumes as string[]).find((v) => v.split(":")[1] === "/data")!;
    const name = mount.split(":")[0];
    expect(name).toMatch(/^[a-z][\w-]*$/);
    expect(Object.keys(doc.volumes)).toContain(name);
  });

  test("TrueNAS uses a named volume, port 3100, and no compose interpolation", () => {
    const text = read("packaging/truenas/docker-compose.yml");
    const doc = YAML.parse(text);
    const svc = doc.services.gatehouse;
    const mount = (svc.volumes as string[]).find((v) => v.split(":")[1] === "/data")!;
    expect(Object.keys(doc.volumes)).toContain(mount.split(":")[0]);
    expect((svc.ports as string[]).some((p) => p.endsWith(":3100"))).toBe(true);
    // Install via YAML does not read .env, so a ${VAR} would land literally.
    expect(text.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n")).not.toContain("${");
    expect(text).toContain(SINGLE);
  });

  test("the image carries a passwd entry for the TrueNAS apps uid 568", () => {
    expect(read("Dockerfile")).toMatch(/useradd[^\n]*-u 568/);
  });

  test("umbrel-app.yml version equals VERSION and its description carries the single-instance sentence", () => {
    const m = YAML.parse(read("packaging/umbrel/umbrel-app.yml"));
    expect(m.version).toBe(VERSION);
    expect(m.description).toContain(SINGLE);
    expect(m.port).toBe(3100);
    expect(m.id).toBe("gatehouse");
  });

  test.each(["packaging/unraid/gatehouse.xml", "packaging/umbrel/umbrel-app.yml", "packaging/casaos/docker-compose.yml"])(
    "%s description carries the single-instance sentence",
    (p) => {
      expect(read(p)).toContain(SINGLE);
    },
  );

  test("no template contains a private address", () => {
    for (const p of [...TEMPLATES, "packaging/README.md"]) {
      const text = read(p);
      expect(text).not.toMatch(/\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
      expect(text).not.toMatch(/\b192\.168\.\d{1,3}\.\d{1,3}\b/);
      expect(text).not.toMatch(/\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/);
      expect(text).not.toMatch(/\.(lan|home\.arpa)\b/);
    }
  });

  test.each(TEMPLATES.filter((p) => p.includes("compose")))("%s mounts a persistent volume at /data", (p) => {
    const doc = YAML.parse(read(p));
    const mounts: { source: string; target: string }[] = [];
    for (const svc of Object.values<any>(doc.services)) {
      for (const v of svc.volumes ?? []) {
        if (typeof v === "string") {
          const [source, target] = v.split(":");
          mounts.push({ source, target });
        } else mounts.push({ source: v.source ?? "", target: v.target });
      }
    }
    const data = mounts.filter((m) => m.target === "/data");
    expect(data.length).toBe(1);
    expect(data[0].source.trim()).not.toBe("");
  });

  test("no template uses an em dash", () => {
    for (const p of [...TEMPLATES, "packaging/README.md"]) expect(read(p)).not.toContain(String.fromCharCode(0x2014));
  });
});
