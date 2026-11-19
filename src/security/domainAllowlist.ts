/**
 * Match a request URL against a secret's `allowed_domains` entries.
 *
 * Entry forms (validated on write by src/ui/list-validate.js, kind "host"):
 *   example.com        that host and any subdomain, any port
 *   *.example.com      subdomains only
 *   host:port          as above, restricted to that port
 *   10.0.0.50          an IP literal (exact), any port
 *   [fd00::1]:8080     IPv6 literal with a port (brackets optional without one)
 *   10.0.0.0/24        any IP-literal host inside the range
 *
 * The URL's port defaults from its scheme (http 80, https 443). An entry that
 * cannot be parsed matches nothing.
 */
import { ipMatchesAllowlist } from "../auth/cidr";

const DEFAULT_PORTS: Record<string, string> = { "http:": "80", "https:": "443" };

function stripBrackets(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function entryMatches(entry: string, hostname: string, port: string): boolean {
  if (entry.includes("/")) {
    // CIDR range: only meaningful when the URL host is an IP literal.
    try {
      return ipMatchesAllowlist(stripBrackets(hostname), [entry]);
    } catch {
      return false;
    }
  }

  let rest = entry;
  const wildcard = rest.startsWith("*.");
  if (wildcard) rest = rest.slice(2);

  // Bare IPv6 (two or more colons, no brackets) cannot carry a port.
  if (!rest.startsWith("[") && (rest.match(/:/g) || []).length >= 2) rest = `[${rest}]`;

  // Let the URL parser canonicalise host and port (case, IPv6 form).
  let parsed: URL;
  try {
    parsed = new URL(`http://${rest}`);
  } catch {
    return false;
  }
  if (parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.username) return false;

  // `new URL` drops an explicit :80 for http, so read the port from the text.
  const portMatch = /:(\d{1,5})$/.exec(rest.startsWith("[") ? rest.slice(rest.indexOf("]") + 1) : rest);
  if (portMatch && portMatch[1] !== port) return false;

  const entryHost = parsed.hostname.toLowerCase();
  if (wildcard) return hostname.endsWith(`.${entryHost}`);
  return hostname === entryHost || hostname.endsWith(`.${entryHost}`);
}

export function hostAllowed(
  url: string | URL,
  entries: string[]
): { allowed: boolean; hostname: string } {
  let parsed: URL;
  try {
    parsed = typeof url === "string" ? new URL(url) : url;
  } catch {
    return { allowed: false, hostname: "invalid" };
  }
  const hostname = parsed.hostname.toLowerCase();
  if (entries.length === 0) return { allowed: true, hostname };
  const port = parsed.port || DEFAULT_PORTS[parsed.protocol] || "";
  const allowed = entries.some((e) => entryMatches(e.trim(), hostname, port));
  return { allowed, hostname };
}
