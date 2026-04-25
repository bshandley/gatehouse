import { Hono } from "hono";
import { VERSION } from "../version";

/**
 * Version-check endpoint: tells the UI whether a newer Gatehouse release
 * is available on GitHub. The check is server-side so each Gatehouse
 * instance makes one outbound call per cache window (1h) regardless of
 * how many UI tabs are open. The result is cached in process memory.
 *
 * Operators on airgapped homelabs can disable the outbound call entirely
 * with GATEHOUSE_UPDATE_CHECK=false; the endpoint still returns the
 * current version with a check_disabled flag so the UI can branch
 * cleanly without a request error.
 */

const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const RELEASES_URL =
  "https://api.github.com/repos/bshandley/gatehouse/releases/latest";

interface VersionCheckResult {
  current: string;
  latest?: string | null;
  has_update?: boolean;
  release_url?: string;
  published_at?: string;
  check_disabled?: boolean;
  check_failed?: boolean;
  no_releases?: boolean;
  error?: string;
}

let cache: { value: VersionCheckResult; expiresAt: number } | null = null;

/** Test-only: drop the cached result so a subsequent call re-fetches. */
export function _resetVersionCheckCache(): void {
  cache = null;
}

/**
 * Compare two semver-like strings ("0.8.10", "v0.8.2"). Returns negative
 * if a < b, zero if equal, positive if a > b. Tolerates a leading "v"
 * and missing components (treats "0.8" as "0.8.0"). Does NOT understand
 * pre-release suffixes; we don't ship any.
 */
export function compareVersions(a: string, b: string): number {
  const pa = a
    .replace(/^v/, "")
    .split(".")
    .map((n) => parseInt(n, 10) || 0);
  const pb = b
    .replace(/^v/, "")
    .split(".")
    .map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const da = pa[i] ?? 0;
    const db = pb[i] ?? 0;
    if (da !== db) return da - db;
  }
  return 0;
}

/**
 * Internal: hit the GitHub API for the latest release. Extracted so
 * tests can swap it out with a stub.
 */
async function fetchLatestRelease(): Promise<{
  tag_name: string;
  html_url: string;
  published_at: string;
} | null | "not_found"> {
  const res = await fetch(RELEASES_URL, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "gatehouse-update-check",
    },
    signal: AbortSignal.timeout(5000),
  });
  if (res.status === 404) return "not_found";
  if (!res.ok) {
    throw new Error(`GitHub API returned ${res.status}`);
  }
  return (await res.json()) as any;
}

export interface VersionRouterOptions {
  /** Override the upstream fetch (used by tests). */
  fetcher?: typeof fetchLatestRelease;
}

export function versionRouter(opts: VersionRouterOptions = {}) {
  const router = new Hono();
  const fetcher = opts.fetcher ?? fetchLatestRelease;

  router.get("/check", async (c) => {
    // Opt-out for airgapped deployments. Always echo the current version
    // so the UI can still display it.
    if (process.env.GATEHOUSE_UPDATE_CHECK === "false") {
      return c.json({ current: VERSION, check_disabled: true } satisfies VersionCheckResult);
    }

    if (cache && cache.expiresAt > Date.now()) {
      return c.json(cache.value);
    }

    try {
      const release = await fetcher();
      let result: VersionCheckResult;
      if (release === "not_found" || !release) {
        result = { current: VERSION, latest: null, has_update: false, no_releases: true };
      } else {
        const latest = String(release.tag_name || "").replace(/^v/, "");
        result = {
          current: VERSION,
          latest,
          has_update: latest.length > 0 && compareVersions(latest, VERSION) > 0,
          release_url: release.html_url,
          published_at: release.published_at,
        };
      }
      cache = { value: result, expiresAt: Date.now() + CACHE_TTL_MS };
      return c.json(result);
    } catch (e: any) {
      // Soft failure: never break the UI on a transient GitHub outage
      // or DNS hiccup. Cache the failure briefly so we don't pound
      // GitHub if it's down.
      const result: VersionCheckResult = {
        current: VERSION,
        check_failed: true,
        error: e.message || "fetch failed",
      };
      cache = { value: result, expiresAt: Date.now() + 5 * 60 * 1000 }; // 5 min
      return c.json(result);
    }
  });

  return router;
}
