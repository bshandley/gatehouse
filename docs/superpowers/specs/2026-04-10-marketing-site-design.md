# Gatehouse Marketing Site Design Spec

**Date:** 2026-04-10
**Status:** Approved (pending written review)
**Target deployment:** GitHub Pages, served from `gatehouse/docs/`, `https://bshandley.github.io/gatehouse/`

## 1. Goal

Build a small, fast, dark-themed marketing site for Gatehouse that:

1. Explains the project to homelabbers in under 30 seconds of scrolling.
2. Hosts the complete documentation (README, agent reference, integrations, concept guides) in a browsable, searchable-by-Ctrl+F format.
3. Links prominently to the GitHub repo.
4. Requires no runtime backend, no CI, no external services. Builds locally, commits to `docs/`, GitHub Pages serves the rest.

Non-goals: search backend, analytics, newsletter signup, blog, multi-language support, light theme.

## 2. Audience

**Primary:** Homelabbers running AI agents on small self-hosted hardware. They want to know: is this easy to deploy, is it secure, does it work with my stack.

Secondary audiences (developers integrating Gatehouse, security-conscious operators) are served by the docs section, not by separate marketing surfaces.

## 3. Tech stack

| Concern | Choice | Reason |
|---|---|---|
| Framework | Astro 5.x | Static output, zero runtime JS by default, native MDX support, built-in Shiki code highlighting. |
| Content format | MDX | Lets us embed Astro components inside markdown when a docs page needs a diagram or interactive element, without losing the simplicity of markdown for 95% of cases. |
| Fonts | `@fontsource/instrument-sans`, `@fontsource/dm-sans`, `@fontsource/jetbrains-mono` | Self-hosted, no Google Fonts network request at runtime. Matches the security ethos of the project. |
| Syntax highlighting | Shiki (built into Astro) with `one-dark-pro` theme | Matches the purple accent of the app UI. Pre-rendered at build time, zero client JS. |
| Heading anchors | `rehype-autolink-headings` | Clickable permalinks on every H2/H3. |
| Search | None in v1. Pagefind can be added later | Ctrl+F is fine for ~10 pages. |
| Build output | `site/dist/` → copied to `docs/` at the project root | GitHub Pages serves from `main` branch `/docs` folder. |
| CI | None in v1 | Developer runs `bun run build:site` locally and commits output. |

## 4. Project layout

```
gatehouse/
├── site/                           # Standalone Astro project
│   ├── package.json                # Site's own deps (Astro, @astrojs/mdx, etc.)
│   ├── astro.config.mjs
│   ├── tsconfig.json
│   ├── scripts/
│   │   └── sync-docs.ts            # Pre-build: copies ../docs/agent-api-reference.md
│   │                               # and ../docs/integrations.md into src/content/docs/
│   ├── public/                     # Static assets (favicon, og-image, screenshots)
│   │   ├── favicon.svg
│   │   ├── og-image.png            # 1200×630 social preview
│   │   └── screenshots/
│   │       ├── dashboard.png
│   │       ├── secrets.png
│   │       └── patterns.png
│   └── src/
│       ├── components/
│       │   ├── Nav.astro
│       │   ├── Footer.astro
│       │   ├── Hero.astro
│       │   ├── ProblemSection.astro
│       │   ├── ProxyFlow.astro      # 3-step diagram
│       │   ├── FeatureGrid.astro
│       │   ├── Screenshots.astro
│       │   ├── QuickStart.astro
│       │   ├── Sidebar.astro        # Docs sidebar
│       │   ├── TableOfContents.astro
│       │   ├── CodeBlockCopy.astro  # Copy button (tiny inline script)
│       │   └── Callout.astro        # note/warning/danger admonition
│       ├── layouts/
│       │   ├── Base.astro           # Top nav, footer, dark theme CSS vars
│       │   └── Docs.astro           # Base + sidebar + TOC rail
│       ├── content/
│       │   └── docs/
│       │       ├── getting-started.mdx
│       │       ├── concepts.mdx
│       │       ├── authentication.mdx
│       │       ├── web-ui.mdx
│       │       ├── providers.mdx
│       │       ├── for-agents.mdx   # Synced from ../docs/agent-api-reference.md
│       │       ├── integrations.mdx # Synced from ../docs/integrations.md
│       │       ├── security.mdx
│       │       └── api-reference.mdx
│       ├── pages/
│       │   ├── index.astro          # Landing page
│       │   ├── docs/
│       │   │   ├── index.astro      # Redirect to getting-started
│       │   │   └── [...slug].astro  # Docs page renderer
│       │   └── 404.astro
│       └── styles/
│           ├── global.css           # CSS variables, base styles
│           ├── typography.css
│           └── prose.css            # Markdown content styles
└── docs/                            # GitHub Pages publishes from here
    ├── agent-api-reference.md       # Existing canonical source (stays)
    ├── integrations.md              # Existing canonical source (stays)
    ├── superpowers/                 # Existing (spec lives here)
    └── [built site files]           # Produced by `bun run build:site`
```

**Build flow:**

```
1. cd site && bun install                    (first time only)
2. bun run site:build                        (from project root)
   ├─ site/scripts/sync-docs.ts              (copies existing .md into src/content/docs/)
   ├─ astro build                            (produces site/dist/)
   └─ cp -r site/dist/* ../docs/             (excluding the existing .md files)
3. git add docs/ && git commit                (commit built output)
4. git push                                   (GitHub Pages picks it up)
```

A single `bun run site:build` script at the project root runs the whole chain. Since GitHub Pages serves from `docs/`, the existing canonical markdown files (`agent-api-reference.md`, `integrations.md`) **must be preserved** during the copy step. The sync script reads them, the build copies over the rest, and the `site:build` script uses a file list that excludes any existing `.md` at the `docs/` root.

## 5. Information architecture

### Top nav (all pages)

- **Gatehouse logo** (links to `/`)
- **Docs** (links to `/docs/getting-started/`)
- **Agents** (links to `/docs/for-agents/`)
- **GitHub** (external, ↗ icon)

Sticky on scroll. No theme toggle.

### Pages

```
/                                 Landing page (marketing)
/docs/                            Redirect to /docs/getting-started/
/docs/getting-started/            Docker run, first secret, first lease
/docs/concepts/                   Proxy mode, leasing, dynamic secrets, pattern learning, policies
/docs/authentication/             Root token, users, AppRoles, TOTP
/docs/web-ui/                     Screenshots and walkthrough of each tab
/docs/providers/                  Dynamic secret provider setup
/docs/for-agents/                 Agent-facing API reference
/docs/integrations/               Harness integration guide
/docs/security/                   Threat model, hardening, master key handling
/docs/api-reference/              REST + MCP reference
404                               Fallback
```

### Docs sidebar

```
GETTING STARTED
  Install
  First secret
  First lease

CORE CONCEPTS
  Proxy mode
  Credential leasing
  Dynamic secrets
  Pattern learning
  Policies & capabilities

USING GATEHOUSE
  Authentication
  Web UI tour
  Dynamic secret providers
  Security & threat model

REFERENCE
  REST API
  MCP tools
  For agents
  Integrations
```

Collapsible section groups. Current page highlighted. Collapses to a hamburger menu on mobile.

### Right rail (docs pages, ≥1280px viewport only)

Auto-generated table of contents from H2/H3 headings. Sticky. IntersectionObserver highlights the current section as the user scrolls.

## 6. Landing page layout

Top to bottom:

1. **Top nav** (sticky).
2. **Hero**: two-column grid. Headline *"Credentials that never leave the vault."*, approved body copy with learning sentence, two CTAs ("Read the docs →" + GitHub link), code preview on the right showing proxy + pattern-learned flow. Full markup in Appendix A.
3. **The problem**: four short declarative lines, centered.
   > *AI agent context windows get logged.*
   > *They get cached.*
   > *They get sent to cloud APIs.*
   > *A credential that enters an agent's memory can end up anywhere.*
4. **How proxy mode works**: 3-step diagram, horizontal on desktop, stacked on mobile.
   - **1. Agent sends a request** → `POST /v1/proxy` with a secret reference, not the secret itself
   - **2. Gatehouse injects the credential** → resolves the reference, forwards upstream
   - **3. Response comes back** → agent sees the API response, never the key
   Short paragraph below explaining the pattern learning loop, with a link to the concepts page.
5. **Feature grid**: 6 cards in a 3×2 grid. Inline SVG icon, one-word title, one-sentence description. Cards:
   - Proxy mode
   - Pattern learning
   - Dynamic secrets
   - Credential leasing
   - MCP + REST
   - Audit & scrubbing
6. **Screenshots section**: 3 UI screenshots (dashboard, secrets view, patterns tab) with captions. Rounded corners, subtle border. Click opens a full-size version in a new tab (no lightbox library).
7. **Quick start**: the `docker run` command from the README in a code block with a copy button. Below: *"That's it. Open localhost:3100, paste your root token, start storing secrets."*
8. **Who it's for**: one paragraph, ~40 words. *"Built for homelabbers running AI agents on Raspberry Pis, Proxmox LXCs, or any small Linux box. Runs in one container. No unsealing ceremony, no Consul cluster, no ops team."*
9. **Footer**: small, three columns. Project (GitHub, License, Issues), Docs (Getting started, Concepts, Agents), About (one sentence + AGPL-3.0 notice). Logo bottom-left.

## 7. Visual design

### Color palette (CSS variables)

Matches the app's palette from `CLAUDE.md`:

```css
--bg-primary:    #0a0a0f;
--bg-secondary:  #12121a;
--bg-tertiary:   #1a1a25;
--bg-card:       #16161f;
--border:        rgba(255, 255, 255, 0.06);
--border-hover:  rgba(255, 255, 255, 0.12);
--text-primary:  #e8e6e3;
--text-secondary:#8a8a95;
--text-tertiary: #55555f;
--accent:        #6c63ff;
--accent-hover:  #7d75ff;
--accent-subtle: rgba(108, 99, 255, 0.1);
--success:       #34d399;
--warning:       #fbbf24;
--danger:        #f87171;
```

### Typography

- **Display (H1, hero)**: Instrument Sans, weight 400-500, letter-spacing -0.02em to -0.03em
- **Body**: DM Sans, 16px base, line-height 1.65
- **Monospace**: JetBrains Mono (code, inline code, path references)
- Italic emphasis in the hero uses Instrument Sans italic for a serif-editorial feel

### Spacing and layout

- Content max-width: 72ch for prose, 1280px for full-width sections
- Vertical rhythm: 2rem between sections on the landing page, 1.5rem between docs page subsections
- Grid: CSS Grid with `auto-fit` for responsive feature cards, fixed 2-column for hero

### Imagery

- 3 screenshots of the running web UI, PNG, sized to match the design container
- Favicon: the existing `gatehouse/src/ui/logo.svg` (purple rounded square with white G mark)
- OG image: 1200×630 PNG with the hero headline + logo, generated once by hand

## 8. Copy direction

**Voice:**
- Precise, not playful
- Homelab-aware, not enterprise
- Concrete, not abstract
- No em dashes anywhere
- No marketing clichés ("revolutionize", "game-changing", "next-generation", "seamlessly", "empowers")

**Section headlines (landing page):**
- Hero: *Credentials that never leave the vault.*
- Problem: *Agent memory is not private.*
- Proxy flow: *Three steps. Key stays home.*
- Feature grid: *Everything you need in one container.*
- Who it's for: *Built for homelabs.*

**Docs pages preserve the existing markdown voice** (which is already good). The site renders them, it doesn't rewrite them.

## 9. Docs rendering details

### Content sync

A pre-build script (`site/scripts/sync-docs.ts`) runs before `astro build` and copies the existing canonical markdown files into the Astro content collection, adding frontmatter as it goes:

| Source | Destination | Added frontmatter |
|---|---|---|
| `docs/agent-api-reference.md` | `site/src/content/docs/for-agents.mdx` | title: "For Agents", sidebar_order, sidebar_group |
| `docs/integrations.md` | `site/src/content/docs/integrations.mdx` | title: "Integrations", sidebar_order, sidebar_group |

Other docs pages are written fresh as `.mdx` files in `site/src/content/docs/` and borrow content from the README where appropriate.

### MDX frontmatter schema

```yaml
---
title: string          # Page title (H1 and browser tab)
description: string    # Meta description, shown in OG tags
sidebar_order: number  # Position within sidebar group
sidebar_group: string  # Group name (GETTING STARTED | CORE CONCEPTS | ...)
---
```

Astro content collections enforce this schema via Zod.

### Rendering behavior

- **Code blocks**: Shiki `one-dark-pro` theme. Line numbers on blocks >8 lines. Copy button on every block (tiny vanilla JS in a shared component).
- **Headings**: auto-anchored via `rehype-autolink-headings`.
- **Tables**: sticky header if overflowing vertically, `overflow-x: auto` on mobile.
- **Admonitions**: `<Callout type="note">`, `type="warning"`, `type="danger"` MDX component. Purple left border for note, amber for warning, red for danger.
- **Inline code**: JetBrains Mono, `--bg-tertiary` background, no border, slight padding.
- **Internal links**: subtle underline on hover.
- **External links**: ↗ icon appended, `target="_blank" rel="noopener"`.

### Table of contents (right rail)

- Generated at build time from H2/H3 headings in the current page
- Sticky position
- IntersectionObserver (~15 lines of inline JS) highlights the current section
- Hidden below 1280px viewport

### Sidebar behavior

- Collapsible group headers with chevron animation
- Current page highlighted with a left accent border
- Mobile: hamburger at top-left, sidebar slides in from left, overlays content

### 404 page

```
That page walked off.
[Back to docs index]
```

Dark background, centered, same nav/footer as everywhere else.

## 10. Performance budget

- **First Contentful Paint**: <1s on a local network (static HTML, no render-blocking resources)
- **Total page weight**: <150KB per page (HTML + CSS + fonts + any inline JS)
- **JavaScript**: zero runtime JS on the landing page. Docs pages include only the TOC scroll-spy (~500 bytes) and code-block copy buttons (~500 bytes). No frameworks, no hydration.
- **Fonts**: Self-hosted, `font-display: swap`, subset to Latin.
- **Images**: Screenshots are lossy PNGs, max 1600px wide, no larger than 200KB each.

## 11. Build and deploy workflow

### First time

```bash
cd gatehouse/site
bun install              # installs Astro + deps (site has its own node_modules)
cd ..
bun run site:build       # runs sync-docs, astro build, copies to docs/
```

### Every update

```bash
bun run site:build
git add docs/ site/src/
git commit -m "site: <what changed>"
git push
```

GitHub Pages picks up the new `docs/` folder and publishes within a minute.

### Scripts added to root `package.json`

```json
{
  "scripts": {
    "site:build": "cd site && bun run sync-docs && astro build && node scripts/publish.mjs",
    "site:dev": "cd site && astro dev"
  }
}
```

`scripts/publish.mjs` copies `site/dist/*` into `docs/` while preserving existing canonical markdown files (`agent-api-reference.md`, `integrations.md`, and the `superpowers/` directory).

### GitHub Pages configuration

- Source: Deploy from branch
- Branch: `main`
- Folder: `/docs`
- Custom domain: none for v1 (can be added later)

## 12. Out of scope for v1

The following are explicitly not included and can be added later:

- Search (Pagefind or similar)
- Analytics
- Custom domain
- CI-based builds (GitHub Actions)
- Blog / changelog
- Multi-language support
- Light theme
- Lightbox for screenshots
- Newsletter signup
- Social share buttons

## 13. Success criteria

The site is done when:

1. All 11 pages render correctly with dark theme, correct fonts, working navigation.
2. The landing page hero matches the approved v5 mockup.
3. Docs pages pull from the existing markdown sources via the sync script.
4. `bun run site:build` produces a working `docs/` folder without clobbering existing canonical markdown files.
5. GitHub Pages serves the site and all internal links resolve.
6. Page weight budget is met (see section 10).
7. No console errors in the browser on any page.

---

## Appendix A: Approved hero markup

Reference for the implementing agent. Final CSS belongs in the Astro component, not inline, but the structure and copy are locked.

**Structure:**
- `.hero` container, two-column grid (1.2fr / 0.8fr), 3rem gap
- **Left column:**
  - `.eyebrow`: "A SECRETS VAULT FOR AI AGENTS" (JetBrains Mono, uppercase, `--accent`)
  - `h1`: "Credentials that _never leave_ the vault." (Instrument Sans, italic span for "never leave", light purple `#b8b0ff`)
  - `p`: approved body copy (below)
  - Two CTAs: pill-shaped primary ("Read the docs →") + ghost monospace GitHub link
- **Right column:**
  - `.preview` card showing the proxy flow + pattern learned callout (see v5 mockup)

**Body copy (locked):**

> Traditional secret managers hand the key to the client. Gatehouse doesn't. Agents proxy HTTP requests through the vault and get the response back, while the credential stays server-side, out of every context window, log, and tool output. Every successful call is learned as a reusable pattern, so the next agent already knows how to use the API without burning tokens guessing.

**Code preview content (locked):**

```
# Agent asks the vault
POST /v1/proxy
secret: "api-keys/openai"
url:    "api.openai.com/v1/chat"

# Gatehouse injects the key,
# forwards upstream, returns body.
# Agent never touches the secret.

✓ pattern learned
# Next agent queries patterns
# and gets this template back,
# verified and confidence-scored.
```

Full mockup available at `.superpowers/brainstorm/518217-1775864164/content/hero-b-v5.html`.

## Appendix B: Content sources per docs page

| Docs page | Source |
|---|---|
| Getting started | Rewrite from README sections "Quick start" + "Authentication" intro |
| Concepts | Synthesize from README "Why Gatehouse" + "Core features" |
| Authentication | README "Authentication" section (3 methods) |
| Web UI | New content + screenshots |
| Providers | README "Dynamic secrets provider setup" section |
| For agents | Synced verbatim from `docs/agent-api-reference.md` |
| Integrations | Synced verbatim from `docs/integrations.md` |
| Security | README "Security considerations" section |
| API reference | New content: auto-generated tables from the route list in CLAUDE.md |

All pages that are not "synced verbatim" get a `<!-- Generated from README 2026-04-10 -->` comment at the top so future updates know the source of truth.
