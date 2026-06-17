# PenRUSH — download site

Static download/landing site for **PenRUSH** ("don't rush to download.").
Single page + Terms of Use. **Zero** frameworks, **zero** build step, **zero**
third-party scripts, **zero** CDN, **zero** telemetry, **zero** analytics. Open
`index.html` in a browser and it works — there is nothing to compile.

Eating our own dogfood: a supply-chain-security tool ships no external script
tag, no remote font, and no network egress. Everything is self-hosted and the
page is locked down with a strict, self-only Content-Security-Policy.

## Status — DOWNLOADS ARE GATED (not live)

Per Uri's 2026-06-17 decision, real downloads stay **inert** until the PH-2
independent security audit clears. The download button is present but disabled
behind **both** gates (see "Going live" below). No signed binary URL exists yet;
the public repo + signed release are PH-2-gated.

**Do not deploy and do not push** from this state. Local files + local commit
only. Per the global hard rule, **only GODclaude executes `git push`**.

## Files

| Path | Purpose |
|---|---|
| `index.html` | Single-page site: hero, how-it-works, gated download, verify, footer |
| `terms.html` | Full 11-clause Terms of Use (LMO-cleared, verbatim) |
| `styles.css` | Token-faithful stylesheet (`@import`s `fonts/fonts.css`) |
| `app.js` | Vanilla dual-gate download logic (no deps) |
| `LICENSE` | Apache License 2.0 (copy of repo root `LICENSE`) |
| `fonts/` | 5 self-hosted IBM Plex woff2 + `fonts.css` + OFL licenses |
| `assets/lockups/` | Brand lockups (SVG; wordmark pre-outlined to paths) |
| `assets/icons/` | Favicons + PWA/apple-touch icons |
| `_headers` | Cloudflare Pages response headers (edge CSP + security + cache) |
| `_redirects` | Cloudflare Pages canonical-host + alias redirects |

## Legal text is verbatim and locked

The consent-checkbox string (47 words) in `index.html` and all 11 ToS clauses in
`terms.html` are reproduced **verbatim** from the LMO clearance at
`knowledge/lmo/clearances/penrush-trademark-license-consent.md` (§6.2 + §7).
**Do not paraphrase.** Any change requires LMO re-review (D-16 re-clears the
rendered page). The `[date]`, contact-email, and GitHub-repo-link placeholders
are intentionally pending (PH-2 / D-12).

## Content-Security-Policy

Identical policy in two places (kept byte-for-byte in sync):
- `<meta http-equiv="Content-Security-Policy">` in `index.html` and `terms.html`
- `_headers` (server-side, takes precedence, also covers non-HTML assets)

```
default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self';
img-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none';
frame-ancestors 'none'; manifest-src 'self'
```

`connect-src 'none'` means the page provably cannot fetch/XHR/WebSocket anything
— no phone-home is even possible. There is no inline script and no inline style,
so no `'unsafe-inline'` and no nonce/hash are needed. A live download is a
top-level `<a href>` navigation to GitHub Releases, which CSP does not restrict,
so going live needs **no** CSP change.

## Going live (one-line gate flip — PH-2 only)

Downloads are gated by **two** independent conditions, both required:

1. **Build-time flag** in `app.js`: `RELEASE_AVAILABLE` (currently `false`).
2. **User consent**: the checkbox must be ticked.

While `RELEASE_AVAILABLE === false`, the button is inert no matter the checkbox.
When PH-2 clears, edit `app.js`:

```js
var RELEASE_AVAILABLE = true;
var RELEASE_BASE_URL  = "https://github.com/OWNER/REPO/releases/download/v0.1.0/";
var RELEASE_TAG       = "v0.1.0";
```

No other code change is required. Also fill the `[date]` and contact-email
placeholders in `terms.html` and the GitHub footer link in `index.html` at that
time (D-12).

## Deploy (Cloudflare Pages) — DO NOT RUN YET

Target project: **`penrush`** · custom domain: **`penrush.penbag.store`**.

- **Framework preset:** None (static — no build).
- **Build command:** *(empty)*
- **Build output directory:** `site` (this directory)
- **Root directory:** repo root (so the output dir is `site/`)

`_headers` and `_redirects` are picked up automatically by Pages from the output
directory. In `_redirects`, replace `:project.pages.dev` with the real Pages
subdomain once the project is created.

Direct-upload alternative (also gated — do not run): from the repo root,
`wrangler pages deploy site --project-name penrush`. **This is documentation
only. No deploy, no push, until PH-2 clears and GODclaude is handed the push.**

## Verify locally (no server needed)

```sh
# zero external/CDN references (expect: only the prose comments that say "no CDN")
grep -rniE 'googleapis|gstatic|cdn' site/
# zero off-origin <script>/<link>
grep -rniE '<(script|link)[^>]+(src|href)="https?:' site/
```
