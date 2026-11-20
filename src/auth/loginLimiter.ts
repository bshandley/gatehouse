// In-memory failed-login limiter: 5 failures per IP per 60s window.
// One module-level state shared by every login endpoint and the passthrough
// route, so counters are never split across copies.
const failedAttempts = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_MS = 60_000;

/** Test-only: clear all rate-limit state. */
export function _resetRateLimitForTests() {
  failedAttempts.clear();
}

// Periodic cleanup to prevent memory leak from accumulated stale entries
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of failedAttempts) {
    if (now > entry.resetAt) {
      failedAttempts.delete(ip);
    }
  }
}, RATE_LIMIT_WINDOW_MS * 2);

export function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = failedAttempts.get(ip);
  if (!entry || now > entry.resetAt) {
    return true; // Not rate limited
  }
  return entry.count < RATE_LIMIT_MAX;
}

/** Seconds remaining until the rate-limit window resets for this IP. */
export function retryAfterSeconds(ip: string): number {
  const entry = failedAttempts.get(ip);
  if (!entry) return 0;
  const remaining = Math.ceil((entry.resetAt - Date.now()) / 1000);
  return Math.max(1, remaining);
}

export function recordFailure(ip: string) {
  const now = Date.now();
  const entry = failedAttempts.get(ip);
  if (!entry || now > entry.resetAt) {
    failedAttempts.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
  } else {
    entry.count++;
  }
}
