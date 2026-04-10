/**
 * Credential scrubber: detects and redacts common secret patterns
 * from text before it enters an agent's context window.
 *
 * Used by the MCP server to sanitize tool output, and available
 * as an API endpoint for agent harnesses that want server-side scrubbing.
 */

const PATTERNS: { name: string; regex: RegExp }[] = [
  { name: "openai_key", regex: /sk-proj-[A-Za-z0-9_-]{20,}/g },
  { name: "openai_key_legacy", regex: /sk-[A-Za-z0-9]{32,}/g },
  { name: "anthropic_key", regex: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: "github_pat", regex: /ghp_[A-Za-z0-9]{36,}/g },
  { name: "github_token", regex: /gho_[A-Za-z0-9]{36,}/g },
  { name: "github_app", regex: /ghs_[A-Za-z0-9]{36,}/g },
  { name: "aws_access_key", regex: /AKIA[0-9A-Z]{16}/g },
  { name: "aws_secret_key", regex: /[A-Za-z0-9/+=]{40}(?=\s|$|")/g },
  { name: "stripe_key", regex: /sk_live_[A-Za-z0-9]{20,}/g },
  { name: "stripe_test", regex: /sk_test_[A-Za-z0-9]{20,}/g },
  { name: "slack_token", regex: /xoxb-[0-9A-Za-z-]{20,}/g },
  { name: "slack_user", regex: /xoxp-[0-9A-Za-z-]{20,}/g },
  { name: "generic_bearer", regex: /Bearer\s+[A-Za-z0-9._~+/=-]{20,}/g },
  { name: "basic_auth_url", regex: /:\/\/[^:]+:[^@]+@/g },
  { name: "private_key", regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { name: "connection_string", regex: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"']+/g },
];

export interface ScrubResult {
  scrubbed: string;
  redactions: { type: string; position: number }[];
}

export function scrubValue(text: string): ScrubResult {
  const redactions: { type: string; position: number }[] = [];
  let result = text;

  for (const { name, regex } of PATTERNS) {
    result = result.replace(regex, (match, offset) => {
      redactions.push({ type: name, position: offset });
      const prefix = match.slice(0, Math.min(6, match.length));
      return `${prefix}***REDACTED***`;
    });
  }

  return { scrubbed: result, redactions };
}

/**
 * Quick check: does this text contain anything that looks like a credential?
 * Faster than full scrubbing when you just need a boolean.
 * Creates fresh regex instances to avoid lastIndex state bugs with /g flag.
 */
export function containsCredentials(text: string): boolean {
  return PATTERNS.some(({ regex }) => {
    const fresh = new RegExp(regex.source, regex.flags);
    return fresh.test(text);
  });
}
