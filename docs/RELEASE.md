# **PenRUSH** — Release Runbook + Verification Guide

This document covers two audiences:

1. **Maintainers** — how a release is cut (the pipeline, the gates, the manual
   steps).
2. **Users** — how to verify a downloaded binary's SLSA provenance and Sigstore
   signature before trusting it.

> **Release boundary (binding).** No public GitHub repository, no plugin
> marketplace listing, and no download site go live until **PH-2** (the external
> penetration test) passes **and** the LMO E-items clear. The pipeline in
> `.github/workflows/release.yml` is *built and dry-run-able*, but the first real
> tagged release crossing the internet boundary is gated. `git push` is
> **GODclaude-only** (PSS hard rule). See `docs/BUILD-PLAN.md` "Cross-cutting".

---

## v0.2.0 — FIELD-TEST / PRE-AUDIT (Gate 8 default-on + `--forums`)

> **🔴 FIELD-TEST / PRE-AUDIT RELEASE.** v0.2.0 folds in two NEW capabilities to
> exercise them in the field **before** their formal external security
> pentest (**PH-2b**). Both surface a one-line FIELD-TEST notice at runtime.
> Neither is an audited guarantee yet. This build does **not** cross the public
> boundary until PH-2b passes and the LMO E-items clear (see the release-boundary
> note above); `git push` remains **GODclaude-only**.

### 1. Gate 8 (FR-106) — install-time content analysis, now **ON by default**

Chunk 6's **Gate 8** — the first gate that fetches a package payload and
statically scans its install-lifecycle hooks for a fetch-remote-then-execute
pattern (`internal/payload` + `internal/installscan` + `internal/gate/gate8.go`)
— shipped in v0.1.0 behind a default-OFF `gate8_enabled` flag. **v0.2.0 turns it
ON by default** so a normal `penrush check` (and the Claude Code hook) exercises
install-time remote-code detection.

- The config key is now three-state: absent (a v0.1.0 config that predates the
  field) resolves to the v0.2.0 default (**ON**); `"gate8_enabled": false`
  restores the byte-identical-to-v0.1.0 metadata-only path (no payload fetched).
- **Fail-closed** behavior is unchanged: any scan error (SSRF reject,
  decompression bomb, zip-slip, symlink escape, malformed archive, fetch
  failure, timeout) **BLOCKS**, never silently passes.
- **Docker deferral (TD-020) unchanged:** a live docker image-config fetch (OCI
  manifest→config-blob resolution) returns `ErrDockerLiveFetchDeferred` and
  **fails closed** — a docker check blocks with a clear reason rather than a
  false pass. Docker RUN-history detection is implemented and tested; the live
  OCI fetch lands with PH-2b. Tracked in the CTO tech-debt register.

> **🔴 Go-live still gated on PH-2b.** Gate 8 parses *untrusted package payloads*
> (a materially larger attack surface than v0's metadata-only path). v0.2.0
> enabling-by-default is for **field testing**, not a signed public release: FR-106
> must pass PH-2b (cases PA-1…PA-9) before a public v0.2.0 crosses the boundary.

**Honest capability limit (verbatim, binding — LMO D-12).** FR-106 is **static
analysis only**. It is **evadable by obfuscation** (base64/hex URLs, string
concatenation, indirection through a downloaded interpreter) and by
dynamically-constructed commands. It **fails closed on unparseable input**. It
**raises attacker cost; it is not proof of safety.**

### 2. `--forums` — opt-in advisory community-forum scan (DSPC Gate 4b)

`penrush check … --forums` runs an **advisory** cross-forum "community review
research" scan (`internal/forumscan`, a Go port of DSPC Gate 4b): it searches
five free public forums (Hacker News, Stack Exchange, Lobsters, GitHub
Discussions, Bluesky) for prior human discussion of the artifact being
compromised/malicious/hijacked and emits a fail-closed **CLEAN / REVIEW / FLAG**
verdict (CLEAN requires all five successfully searched with zero hits; any
unchecked forum → REVIEW; any red-flag hit → FLAG).

- **Opt-in only.** Without `--forums` nothing changes — the gate stays offline.
- **Advisory.** A **FLAG** means *investigate*; it does **not** change the gate's
  exit code (the offline gate stays authoritative).
- **Honest framing** is printed every run: absence of hits is not proof of
  safety; unchecked forums are named.
- GitHub Discussions needs a free PAT (`$GITHUB_TOKEN` or `gh auth token`);
  without one it is marked UNCHECKED, never fabricated clean.

> **⚠️ Site-copy caveat (for the release owner).** `--forums` makes **outbound
> HTTP** to five public forums. The download site (`site/`) currently states
> **PenRUSH** makes "zero network calls / collects nothing" — true for the gate,
> now inaccurate for this opt-in advisory feature. The site copy must be updated
> to reflect that `--forums` is an opt-in network feature (everything else stays
> offline, zero-telemetry) before a public v0.2.0 ships.

---

## Part 1 — Cutting a release (maintainers)

### Pre-flight

- [ ] `make ci` is green locally (`vet` + reproducible build + `test`).
- [ ] `go test ./...` passes; `govulncheck ./...` is clean.
- [ ] The version you are about to tag follows semver `vX.Y.Z`.
- [ ] The `PlaceholderSubdomain` constant in `internal/registry/client.go` is
      resolved to the real **penbag.store** subdomain if the download site
      (chunk 4b) is going live in the same cycle (otherwise it stays a
      placeholder and only the GitHub Release is the distribution channel).

### Cut the tag

A release is **tag-triggered**. Pushing an annotated semver tag starts
`.github/workflows/release.yml`:

```sh
git tag -a v0.1.0 -m "PenRUSH v0.1.0"
# Push is GODclaude-only and PH-2-gated. Hand off:
#   "GC, please push: tag v0.1.0 to <remote>"
```

### What the pipeline does (automatic)

1. **args** — resolves the commit SHA to stamp into the binary (deterministic).
2. **reproducibility** — on Linux, macOS, and Windows, builds the binary twice
   with identical inputs and asserts the two SHA-256 hashes match. **If any
   platform is non-deterministic, the release fails** (architecture §H.1).
3. **build** — for each of `linux|darwin|windows × amd64|arm64`, the **trusted
   SLSA Go builder** (`builder_go_slsa3.yml@v2.1.0`) compiles the binary inside
   its isolated, provenance-signing environment and uploads each binary plus its
   SLSA Level 3 provenance (`*.intoto.jsonl`) to the GitHub Release for the tag.
4. **checksums-sign** — downloads the binaries, generates `checksums.txt`
   (SHA-256), and **keyless-signs** it with `cosign sign-blob` (a Fulcio
   ephemeral certificate bound to the workflow's OIDC identity; the event is
   logged in Rekor). The signature bundle `checksums.txt.cosign.bundle` is
   attached to the release. **No long-lived signing key exists** (§C.5 / §H.3).

### The `release` Environment (OIDC signing gate, §H.3)

A dedicated **`release-gate`** job is bound to a **protected GitHub Environment
named `release`**, and the two jobs that hold `id-token: write` — `build` (SLSA
provenance signing) and `checksums-sign` (cosign keyless) — both `needs:
release-gate`. Because neither OIDC job can start until the `release` deployment
is approved on `release-gate`, holding `v*`-tag push rights alone is **not**
sufficient to mint a Fulcio certificate or SLSA provenance: the Environment's
protection rules interpose a human/branch-policy gate at `release-gate`,
backstopping the STRIDE single-maintainer-compromise case (arch §H.3, line 401:
"id-token: write confined to the environment-protected release job").

> **Why a separate gate job, not `environment:` on `build`.** GitHub restricts a
> job that *calls a reusable workflow* (`uses: …builder_go_slsa3.yml@v2.1.0`) to
> the keys `name/uses/with/secrets/needs/if/permissions/strategy/concurrency` —
> `environment:` is **not** permitted there and makes the workflow file
> schema-invalid (startup_failure). The gate therefore lives on the normal
> `release-gate` job, and the dependency edge carries the protection to both
> OIDC-minting jobs. The guarantee is identical; only the placement is valid.

**Required protection rules** (configure once, in repo Settings → Environments →
`release`, before the first real tagged release):

- **Deployment tag policy** — restrict to `v*` tags only (no branch deployments).
- **Required reviewers** — at least one. Per the PSS hard rule that `git push`
  (and therefore the tag that triggers this pipeline) is **GODclaude-only**,
  GODclaude is the encoded reviewer; the deployment cannot proceed past
  `release-gate` to the signing jobs until that reviewer approves.
- **No secrets stored** in the Environment — keyless signing uses only the
  ephemeral OIDC token; there is deliberately no long-lived release key (§C.5).

Until these rules are set, the `environment: release` reference on `release-gate`
still creates the gate but with no reviewers it auto-approves — so this
configuration step is a **release pre-flight item**, not optional.

### Post-release (manual)

- [ ] Verify the release yourself using **Part 2** below (dogfood the recipe).
- [ ] Bump the plugin-marketplace pin if/when the marketplace listing is live
      (gated on PH-2 + LMO E-items).
- [ ] If the download site (chunk 4b) is live, confirm its download button points
      at the immutable GitHub-Releases asset URL for this tag and that the
      verification recipe shown there matches Part 2.

### Windows SmartScreen note (§H.4 / §L-2)

v0 Windows binaries are **not** Authenticode-signed. SmartScreen may warn on
first run ("Windows protected your PC" → *More info* → *Run anyway*). Sigstore
covers integrity and provenance, but SmartScreen reputation runs on Authenticode;
buying an OV code-signing certificate reintroduces exactly the long-lived-key
custody problem keyless signing removes. The decision is deferred to Uri with a
CFA cost note (`[NEEDS VERIFICATION]`).

### A note on the one tag-pinned Action

Every third-party Action in this repo is pinned by **full commit SHA** per the
`/lock file` rule — **except** the SLSA Go builder reusable workflow, which is
referenced by its semver **tag** `@v2.1.0`. This is **required**, not an
oversight: the SLSA project documents that the builder "MUST be referenced by tag
in order for the `slsa-verifier` to be able to verify the ref of the trusted
builder's reusable workflow ... the build will fail if you reference it by a
hash" ([slsa-github-generator README @v2.1.0](https://github.com/slsa-framework/slsa-github-generator/blob/v2.1.0/README.md);
upstream tracking: [slsa-verifier#12](https://github.com/slsa-framework/slsa-verifier/issues/12)).
A hash pin would make the provenance **unverifiable** — the tag is the
security-correct pin in this single case.

---

## Part 2 — Verifying a download (users)

You do not need an account, and **PenRUSH** has no telemetry. Anyone can verify a
release is authentic — built by this repository's release workflow and untampered
— with three independent checks. (The download site planned for a **penbag.store**
subdomain will show this same recipe next to the download button.)

Set these once (replace `OWNER/REPO` with the real repository and `TAG` with the
release tag, e.g. `v0.1.0`):

```sh
REPO="OWNER/REPO"
TAG="v0.1.0"
BIN="penrush-linux-amd64"   # or your platform's artifact
```

### Check 1 — SHA-256 checksum

```sh
# Download the binary, checksums, and the cosign bundle from the release, then:
sha256sum --check --ignore-missing checksums.txt
# Expect: penrush-linux-amd64: OK
```

### Check 2 — Sigstore signature (cosign keyless)

Confirms the checksums file was signed by **this repo's release workflow**, not
by anyone else. Requires [`cosign`](https://docs.sigstore.dev/system_config/installation/).

```sh
cosign verify-blob \
  --bundle checksums.txt.cosign.bundle \
  --certificate-identity-regexp "^https://github.com/${REPO}/\.github/workflows/release\.yml@refs/tags/${TAG}$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
# Expect: Verified OK
```

The OIDC issuer for GitHub Actions tokens is
`https://token.actions.githubusercontent.com`, and the certificate identity is
the release workflow's path at the release tag — so a signature minted by any
other workflow, repo, or branch fails this check.

### Check 3 — SLSA Level 3 provenance

Confirms the binary itself was produced by the trusted SLSA builder from this
repo. Requires [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier).

```sh
slsa-verifier verify-artifact "$BIN" \
  --provenance-path "${BIN}.intoto.jsonl" \
  --source-uri "github.com/${REPO}" \
  --source-tag "$TAG"
# Expect: PASSED: SLSA verification passed
```

If **all three** pass, the artifact is authentic and unmodified. If any fails, do
**not** run the binary — report it via [`SECURITY.md`](../SECURITY.md).

---

## Reference — pinned third-party Actions (verified 2026-06-17)

| Action | Tag | Full commit SHA | Committed |
|---|---|---|---|
| `actions/checkout` | v5 | `93cb6efe18208431cddfb8368fd83d5badbf9bfd` | 2025-11-13 |
| `actions/setup-go` | v6 | `4a3601121dd01d1626a1e23e37211e3254c1c06c` | 2026-03-17 |
| `sigstore/cosign-installer` | v4.1.2 | `6f9f17788090df1f26f669e9d70d6ae9567deba6` | 2026-05-07 |
| `slsa-framework/slsa-github-generator` (Go builder) | **v2.1.0 (tag — required, see above)** | resolves to `f7dd8c54c2067bafc12ca7a55595d5ee9b75204a` | 2025-02-24 |

`govulncheck` is installed at the pinned version `v1.1.4` (not `@latest`).
