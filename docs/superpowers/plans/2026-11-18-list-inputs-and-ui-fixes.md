# List inputs and UI fixes: plan

Spec: `docs/superpowers/specs/2026-11-18-list-inputs-and-ui-fixes-design.md`

Tests first for every task that has automated coverage. Commit and push the
branch to `origin` after each task. Squash-merge to `main` at the end.

## Chunk 1: validation and matching (server)

- [x] **1. Shared validators.** `src/ui/list-validate.js`: `splitList(text)`,
      `validateEntry(kind, entry)`, `parseList(kind, text)`,
      `normalizeList(kind, text)`. Test: `test/listValidate.test.ts`.
- [x] **2. Domain matcher.** `src/security/domainAllowlist.ts`:
      `hostAllowed(url, entries)`. Replace the inline matchers in
      `src/api/proxy.ts` and `src/mcp/server.ts`. Test:
      `test/domainAllowlist.test.ts`, plus proxy tests for `host:port`,
      `*.domain`, and CIDR.
- [x] **3. Validate metadata on write.** `src/secrets/metadataValidation.ts`
      used by POST, PATCH, bulk import, and MCP put. Tolerant splitting in the
      three `auto_approve_from_ip` readers and the prefix readers. Test:
      `test/secrets.metadataValidation.test.ts`.

## Chunk 2: the list input (UI)

- [x] **4. Component.** `src/ui/list-input.js` (`window.ListInput.mount`),
      CSS in `index.html`, routes for both modules in `src/index.ts`. Test:
      route test in `test/uiAssets.test.ts`.
- [x] **5. Secret form.** Allowed domains, path prefixes, and auto-approve IPs
      in the create and edit dialogs. Rename the label to "Auto-approve from
      IPs". Fix the placeholder.
- [x] **6. AppRole allowlist.** "Allowed source IPs" in create and edit, sent
      as `ip_allowlist`. Show it in the AppRoles table.
- [x] **7. Policy paths.** Comma, space, Tab, blur, and paste commit in the
      existing path input. Validation against the policy path rule.
- [x] **8. Dynamic secrets.** Grants, roles, principals, extensions, allowed
      hosts use kind `word`, joined with `,`.

## Chunk 3: shell fixes (UI and server)

- [x] **9. Dialogs.** Escape, focus trap and restore, dialog roles, pinned
      action row, label association.
- [x] **10. Phone drawer.** Top bar and drawer below 700px.
- [x] **11. Fonts.** Files in `src/ui/fonts/`, `/ui/fonts/:file` route with an
      allowlist, `@font-face` rules, Google links removed. Test in
      `test/uiAssets.test.ts`.
- [x] **12. Event stream.** Disable the idle timeout for `/v1/events`.

## Chunk 4: verify and ship

- [x] **13. Browser verification.** Drive a disposable instance: chip input
      keys and paste, invalid entry blocks save, dialogs, drawer at 390px, no
      third-party requests, event stream alive past 30s.
- [x] **14. Docs.** `web-ui.mdx`, `api-reference.mdx`,
      `docs/agent-api-reference.md`, `AGENTS.md`, README where they describe
      allowed domains or list fields. Rebuild the site.
- [x] **15. Release.** `VERSION` and `package.json` to 0.21.0, `CHANGELOG.md`,
      squash-merge, push `main` to both remotes, tag `v0.21.0`, push the tag
      to both.
