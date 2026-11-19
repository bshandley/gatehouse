# List inputs and UI fixes

Date: 2026-11-18
Status: approved in chat (single thumbs-up on a consolidated proposal, at the
maintainer's request, in place of a question-by-question brainstorm)
Target release: 0.21.0

## Problem

Entering lists in the web UI is inconsistent and unvalidated.

- Policy paths use a chip input that commits only on Enter. Comma, space, and
  paste do nothing, so entries go in one at a time.
- Every other list is a plain text box: allowed domains, allowed path prefixes,
  "Auto-approve from IP", and the dynamic-secret grants, roles, principals,
  extensions, and allowed hosts. Nothing is validated on the client or the
  server. A mistyped or space-separated list saves and then never matches.
- The allowed-domains matcher compares the URL hostname to each entry and
  nothing else. Two forms the product itself advertises are dead:
  - `host:port` (used in the agent reference example) never matches, because
    the hostname has no port.
  - `*.example.org` (the form's own placeholder) never matches.
  A homelab operator scoping a key to `10.0.0.50:5230` gets a secret that
  blocks every request.
- The AppRole IP allowlist exists in the API (`ip_allowlist`) and has no UI.

A walk-through of every page and dialog in a headless browser found five more
defects, fixed in the same release because they sit in the same file:

- Dialogs do not close on Escape, do not trap focus, are not announced as
  dialogs, and scroll their Save and Cancel buttons out of view when long.
- Below 700px the sidebar is hidden and nothing replaces it. There is no way
  to navigate on a phone.
- The UI loads its fonts from Google. With that host unreachable the page
  blocked for the full navigation timeout in testing. A secrets vault should
  not call a third party to render its own admin UI.
- The live event stream (`GET /v1/events`) is cut every 10 seconds: Bun's
  default idle timeout is 10s and the heartbeat is 20s.
- Half the form labels are not associated with their inputs.

## Decisions

### One list input

A single chip-input component, used for every multi-value field. It behaves
like the recipient field of a mail client, which is the convention users
already know:

- Enter, comma, space, Tab, or blur commits the current text as an entry.
- Paste splits on commas, whitespace, and newlines.
- Backspace in an empty input removes the last chip. Each chip has a remove
  button. Duplicates are dropped.
- Each entry is validated by kind as it is committed. An invalid entry renders
  as an error chip with the reason, and the form refuses to save while one
  exists.

Kinds and rules:

| Kind | Used by | Accepts |
|---|---|---|
| `cidr` | Auto-approve from IPs, AppRole IP allowlist | IPv4 or IPv6 address, optionally with a prefix length |
| `host` | Allowed domains | hostname, `*.hostname`, IPv4, `[IPv6]`, each with optional `:port`; or a CIDR |
| `pathPrefix` | Allowed path prefixes | starts with `/`, no whitespace |
| `policyPath` | Policy rule paths | `[A-Za-z0-9/_*-]+` |
| `word` | Dynamic-secret lists | non-empty, no whitespace or comma |

Validation rules live in one plain-JS module, `src/ui/list-validate.js`, with
no DOM access at import. The browser loads it as a module and the server
imports the same file, so the two cannot drift.

### Server validates on write

`POST` and `PATCH /v1/secrets/:path`, the bulk import, and the MCP
`gatehouse_put` tool validate `allowed_domains`, `allowed_path_prefixes`, and
`auto_approve_from_ip`. An invalid entry returns 400 naming the key and the
entry. Valid lists are normalised to `a, b, c`.

The stored format does not change: these stay comma-separated strings in
secret metadata, and `ip_allowlist` stays a JSON array. No migration. Existing
values are not rewritten or rejected until the next write to that secret.

Readers become tolerant: they split on commas and whitespace, so a
space-separated list written before this release starts to work.

### Allowed domains match what they say

A new `src/security/domainAllowlist.ts` replaces the two inline copies of the
matcher (REST proxy and MCP proxy):

- `example.com`: that host and any subdomain, any port. Unchanged.
- `*.example.com`: subdomains only.
- `host:port`: as above, restricted to that port. The URL's port defaults from
  its scheme (80, 443).
- IP literals are matched exactly. `[::1]:8080` for IPv6 with a port.
- `10.0.0.0/24`: any IP-literal host inside the range.

This only loosens entries that previously matched nothing. No entry that
matched before stops matching.

### AppRole IP allowlist in the UI

The create and edit AppRole dialogs gain an "Allowed source IPs" field (kind
`cidr`), wired to the existing `ip_allowlist` API field. Empty means no
restriction, as today. This is a restriction on where an AppRole may log in
from. It is not a grants or auto-policy feature and writes no policies.

### Dialogs

One delegated handler set, applied to every `.modal-overlay`:

- Escape closes the topmost dialog.
- Focus moves into the dialog on open, is trapped while open, and returns to
  the opener on close.
- `role="dialog"`, `aria-modal="true"`, labelled by the dialog title.
- The action row is pinned to the bottom of the dialog; the body scrolls.

Labels without a `for` attribute are associated with the single control in
their form group when a dialog or page renders.

### Phone layout

Below 700px a top bar shows the product name and a menu button. The button
opens the existing sidebar as a drawer over the content. Choosing a page or
tapping the backdrop closes it.

### Fonts

DM Sans, Instrument Sans, and JetBrains Mono (all SIL OFL) are served from
`/ui/fonts/` as latin woff2 files checked into `src/ui/fonts/`. The Google
Fonts links are removed. The UI makes no third-party requests.

### Event stream

`GET /v1/events` disables the idle timeout for its own request
(`server.timeout(req, 0)`). The global timeout stays at its default.

## Out of scope

- Visual redesign, page restructuring, a framework, or splitting the
  single-file UI.
- Changing how policies are authored or attached.
- CIDR or port syntax for the AppRole allowlist beyond what `validateCIDRs`
  already accepts.

## Testing

- Unit tests for every validator kind and for the list splitter.
- Unit tests for the domain matcher, including the previously dead forms.
- API tests: 400 on invalid metadata lists for POST, PATCH, bulk, and MCP put;
  normalisation of valid lists; tolerant reads.
- Route tests for `/ui/list-validate.js`, `/ui/list-input.js`, and
  `/ui/fonts/*` (including path traversal).
- The chip input's DOM behaviour, dialogs, the phone drawer, and the event
  stream are verified by driving a disposable instance in headless Chromium.
  CI has no browser, so that check is manual and recorded in the build log.
