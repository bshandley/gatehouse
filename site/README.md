# Gatehouse Marketing Site

Static Astro site published to GitHub Pages from the root `docs/` folder.

## Development

```bash
bun run site:dev      # from the repo root
```

## Build

```bash
bun run site:build    # from the repo root
```

Runs sync-docs, astro build, and publishes to `docs/` while preserving `docs/agent-api-reference.md`, `docs/integrations.md`, and `docs/superpowers/`.

## Screenshots (manual step)

The landing page references three screenshots and an OG image in `site/public/`:

- `screenshots/dashboard.png`
- `screenshots/secrets.png`
- `screenshots/patterns.png`
- `og-image.png` (1200x630)

These ship as 1x1 placeholders. To replace them:

1. Start a local Gatehouse instance with some sample data.
2. Take screenshots of the Dashboard, Secrets, and Patterns tabs at 1600x1000 viewport.
3. Save them as PNGs in `site/public/screenshots/` with the filenames above (lossy compressed to under 200KB each).
4. For the OG image, design a 1200x630 PNG with the hero headline and the logo, save to `site/public/og-image.png`.
5. Rebuild: `bun run site:build`.
