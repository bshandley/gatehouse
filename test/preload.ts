// Loaded before every test file (see [test] preload in bunfig.toml).
//
// The login, onboarding and rotation rate limiters are module-level state
// keyed by source IP. Bun runs all test files in one process, so without a
// reset the hits one test leaves on an IP count against every later test, in
// every later file, and whether a test sees 429 depends on file order.
import { beforeEach } from "bun:test";
import { _resetRateLimitForTests } from "../src/api/auth";
import { _resetOnboardRateLimits } from "../src/api/onboard";
import { _resetRotateRateLimits } from "../src/api/rotate";

beforeEach(() => {
  _resetRateLimitForTests();
  _resetOnboardRateLimits();
  _resetRotateRateLimits();
});
