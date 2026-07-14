# **PenRUSH** — Build Plan (chunks 2–N)

| Field | Value |
|---|---|
| **Product** | **PenRUSH** (internal codename: DSPC) — *"don't rush to download"* |
| **Document** | D-7 incremental build roadmap — chunk-by-chunk Definition of Done |
| **Status** | Living plan. Chunks 1–5 ✅ DONE + green; **v0.1.0 LAUNCHED** (public, metadata-only). **Chunk 6 = v-next, PLAN ONLY — GATED** (§Chunk 6 below). |
| **Upstream** | Architecture v1.0-RATIFIED (`knowledge/cto/architecture/penrush-phase-0.5.md`) · PRD v1.0/v1.1 (`MD/DSPC-Product-PRD-v0.1.md`) · Execution Plan (`knowledge/pma/specs/penrush/EXECUTION-PLAN.md`) |
| **Author** | **CTO** |
| **Date** | 2026-06-16 |
| **Hard rules carried** | Zero third-party runtime deps (arch §A.2) · fail-closed everywhere (arch §C.6) · dog-food `/cool down` + `/lock file` + DSPC on every dep · PH-2 pentest non-skippable + non-compressible before any public/OSS release (Uri 2026-05-25) · GODclaude-only `git push` · English; **PenBag**/**PSS**/**PBS**/**PenRUSH** bold |

---

## Chunk 1 — Gate engine + first-three ecosystems + CLI — ✅ DONE (green)

**Shipped (verified `go build ./...` exit 0, `go test ./...` PASS, `penrush.exe --help` works):**

- `cmd/penrush/main.go` — single-binary entry, four-surface dispatch (arch §A.3).
- `internal/gate` — gate engine + **Gate 1 (publication age)**, fail-closed order override → cache → live resolve (arch §C.6, §D). `Verdict` shape is the stable seam; G2–G7 land behind it with no engine change.
- `internal/registry` — common hardened client (TLS-only, no insecure flag, size-capped strict decode, retry/backoff, https-only redirects — arch §D.1) + **3 ecosystems**: `npm.go`, `pypi.go`, `github.go` (arch §D.2/§D.3/§D.7). `Resolver` interface is the per-ecosystem seam.
- `internal/config` — JSON config, per-ecosystem cooldown, `on_internal_error: "block"` default (arch §B.4, §L-4).
- `internal/override` — override store: mandatory reason, 30-day hard expiry, exact-key only, no wildcards (arch §B.1, §C.4).
- `internal/audit` — SHA-256 chained append-only log + `audit verify` (arch §B.2, NFR-004) with `internal/redact` redaction.
- `internal/cache` — per-key registry response cache with TTL table (arch §B.3).
- `internal/penrushdir` — `~/.penrush/` path resolution (arch §B).
- `internal/cli` — `check` / `init` / `override` / `stats` subcommands (arch §A.3 direct-CLI surface) + 395-line `cli_test.go`.
- Tests green in `internal/{audit,cli,redact}`; parity-corpus + fuzz + property layers (arch §K) are scheduled into later chunks (see §Cross-cutting below).

**Maps to:** PRD FR-001 (gate-on-install), FR-002 (age check), FR-003 (fail-closed), FR-004 (override w/ reason+expiry), FR-005 (`check` dry-run), NFR-001/002 (latency/fail-closed), NFR-004 (tamper-evident audit). Arch §A, §B, §C.6, §D.1–§D.3/§D.7, §K (partial).

---

## Chunk 2 — Remaining 5 ecosystems (cargo · gem · go · docker · mcp) — ✅ DONE (green)

**Goal:** complete PRD §5.4 / arch §A.6 eight-ecosystem coverage by adding five `Resolver` implementations behind the *unchanged* `registry.Resolver` interface and the *unchanged* `gate.Engine` — proving the §A.6 "one module + one parser rule + fixtures, no engine change" claim.

**Shipped (verified `go vet ./...` clean, `go build ./...` exit 0, `go test ./...` PASS, smoke-run on live registries):**
- `internal/registry/cargo.go` — crates.io `versions[].created_at`; 1 rps token bucket (RFC 3463).
- `internal/registry/rubygems.go` — RubyGems `versions/{gem}.json` `created_at` (fractional-second tolerant); 10 rps bucket; newest-first / prerelease-skip selection.
- `internal/registry/gomod.go` — Go proxy `.info` `Time`; GOPROXY `!`-case-escaping; `@latest` rejected at resolver (lock-file rule, defense-in-depth).
- `internal/registry/docker.go` — Docker Hub tags `tag_last_pushed`/`last_updated`+`digest`; **digest-pin = the enforced control** (passes any registry via a distant-past sentinel so age always clears); non-Hub tag-only → block with digest-discovery hint; full ref parser (`host/ns/name:tag@sha256:...`).
- `internal/registry/mcp.go` — `ErrApprovalRequired` sentinel; **always approval-gated** (registry is preview); enrichment fetched best-effort with an independent 3s timeout and swallowed errors — an unreachable preview registry degrades to "enrichment unavailable", never a transport-block that strands the CLI.
- `internal/registry/ratelimit.go` — stdlib-only token-bucket governor (no `golang.org/x/time/rate` dep), injectable clock/sleep for deterministic timing tests.
- Wiring: `gate.Engine.Resolvers` carries all 8; `internal/cli/check.go` dispatch + `internal/cli/cli.go` `--help`. **Zero change to `gate/gate.go` `Verdict`/`Engine` surface** — only one `errors.Is(ErrApprovalRequired)` reason branch (same shape as the existing `ErrNotFound` branch) + two block-message string updates.
- Tests: 6 fixture-based test files (`httptest.NewTLSServer`, zero live calls in CI), per-ecosystem happy/404/5xx/429 fail-closed paths, docker digest-pass + non-Hub-block, mcp approval+degradation, go case-escaping + `@latest` rejection, token-bucket timing (virtual clock). New-file coverage mean **92.1%** (load-bearing `Resolve` paths 80–100%).

**Scope (per arch §D):**
- `internal/registry/cargo.go` — `GET https://crates.io/api/v1/crates/{name}` → `versions[].created_at`; **1 rps token bucket** specific to this ecosystem (arch §D.4, crates.io RFC 3463 policy); identifying User-Agent already present.
- `internal/registry/rubygems.go` — `GET https://rubygems.org/api/v1/versions/{gem}.json` → `created_at`; 10 rps ceiling (arch §D.5).
- `internal/registry/gomod.go` — `GET https://proxy.golang.org/{module}/@v/{version}.info` → `Time`; module-path case-escaping (`!`-encoding); `@latest` stays forbidden at the parser (arch §D.6, lock-file rule).
- `internal/registry/docker.go` — Docker Hub tags API → `tag_last_pushed`/`last_updated`/`digest`; **non-Hub (ghcr/quay): digest-pinning is the enforced control**, tag-only blocks with digest hint (arch §D.8).
- `internal/registry/mcp.go` — MCP adds stay **explicit-approval-gated** (registry is preview, no hard dep on a preview API); registry metadata used as enrichment only (arch §D.9).
- Command-parser rules for each ecosystem's spec forms (`pkg==`, `cargo add`, `gem install`, `go get mod@ver`, `image@sha256:`) ported from the reference hook semantics (arch §A.5).
- Per-ecosystem rate-limit governors + the degradation matrix behavior (arch §D.10) wired through the shared client.

**Definition of Done:**
- [ ] All 5 resolvers implement `registry.Resolver`; `gate.Engine.Resolvers` map carries all 8; **zero change to `gate/gate.go` `Verdict`/`Engine` surface** (diff confined to `internal/registry/*` + parser + wiring).
- [ ] Recorded-HTTP-fixture integration tests per ecosystem (deterministic, **zero live calls in CI**; respects crates.io 1 rps / RubyGems 10 rps / GitHub limits) — arch §K Integration row.
- [ ] Fail-closed paths covered for each: timeout/5xx/TLS → block; 404 → block ("not found" red flag); 429/403-rate → honor `Retry-After` then block; offline → Gate-7-prior-approval-only (arch §D.10).
- [ ] Docker: digest-pinned passes, tag-only blocks with the digest-discovery hint; non-Hub registries never pass on a forgeable producer-set `created` field alone (arch §D.8).
- [ ] MCP: add blocks pending explicit approval; registry metadata shown as enrichment, never a silent pass (arch §D.9).
- [ ] Per-ecosystem rate-limit governors verified by unit test (token-bucket timing).
- [ ] Unit coverage ≥ 80% on new files (CTO standard, arch §K).
- [ ] `go build ./...` exit 0; `go test ./...` PASS; `go vet ./...` clean.

**Maps to:** PRD FR-002 (all ecosystems), FR-007 (Docker digest pinning), FR-008 (MCP approval gate), FR-010 (offline mode). Arch §A.5, §A.6, §D.4–§D.10, §K.

**Risk / dependency:** none external. Self-contained; the seam is proven in chunk 1. crates.io/RubyGems/Go-proxy/Docker-Hub endpoints already fact-checked in arch Appendix S (2026-06-11) — re-verify freshness at build time per the fact-check rule.

---

## Chunk 3 — Claude Code plugin shim (thin wrapper over the CLI)

**Goal:** ship the Claude Code plugin that registers a `PreToolUse` hook on `Bash`, delegating *all* gate logic to the existing `penrush hook claude-code` subcommand — the OQ-4 thin-shim / R-05 anti-stranding commitment (arch §F, §A.3, §A.4).

**Scope (per arch §F):**
- `internal/cli` (or `internal/hook`) — `penrush hook claude-code` subcommand: read stdin JSON (`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"..."}}`), run the fast-path triage + parser + gate engine, emit the structured `permissionDecision` JSON (`deny`/`allow`/`ask`) as primary, exit-2 as compatibility fallback (arch §A.4). `ask` is the override-UX surface.
- **Panic-recovery wrapper** converting any internal failure into an explicit block, honoring `on_internal_error` config (arch §C.6 — a crashing gate must not become a bypass primitive).
- `penrush-plugin/.claude-plugin/plugin.json` — explicit semver `version`, Apache-2.0, the *entire* permission surface (arch §F.1).
- `penrush-plugin/hooks/hooks.json` — exactly one `PreToolUse` matcher on `Bash`. No skills/agents/MCP/settings overrides (arch §C.7, auditable in ~20 lines).
- `penrush-plugin/bin/penrush-hook` — locator shim only: `penrush` on PATH → exec; absent + not-yet-activated → **non-blocking** notice with verified install recipe; absent + previously-activated → **block** (a vanished working gate is an incident). Never auto-downloads (arch §F.3).
- No-match short-circuit budget honored (< 30 ms p95, arch §J) — the hook fires on every Bash call.

**Definition of Done:**
- [ ] `penrush hook claude-code` parses the documented stdin shape and emits valid `permissionDecision` JSON for deny/allow/ask; exit-2 fallback path tested.
- [ ] Plugin manifest + `hooks.json` validate under `claude plugin validate` (arch §F.2). Permission surface is hooks + bin only (arch §C.7).
- [ ] Locator shim three-state behavior tested: present→exec, absent-fresh→non-blocking notice, absent-activated→block (arch §F.3); `activated: true` recorded after first successful gate activation.
- [ ] Panic-recovery → block verified by a fault-injection test (arch §C.6).
- [ ] No-match short-circuit p95 < 30 ms measured on a benchmark (arch §J).
- [ ] Parity corpus: the internal hook's 22 cases ported as golden tests; 100% parity or documented delta (arch §K Parity row) — the divergence list includes §C.6 fail-mode.
- [ ] `go build ./...` exit 0; `go test ./...` PASS.

**Maps to:** PRD FR-001 (gate fires on install commands via the agent surface), FR-009 (Claude Code integration), FR-004 (`ask` override UX). Arch §A.3, §A.4, §C.6, §C.7, §F, §J, §K.

**Risk / dependency:** Claude Code hooks + plugins references already fact-checked (arch Appendix S). Marketplace *submission* (not packaging) is gated downstream — actual public listing waits on PH-2 + LMO E-items, same as the binary release (chunk 4). Re-verify the hooks/plugins docs at build time.

---

## Chunk 4 — Release pipeline (SLSA-L3 + Sigstore) + CF Pages download site

**Goal:** make a verifiable, reproducible, provenance-signed multi-platform release, and a fully-static checkbox-gated download page on a **penbag.store** subdomain — the no-auth, zero-telemetry distribution path (arch §E, §H).

**Scope (per arch §H + §E):**
- **Reproducible build:** `CGO_ENABLED=0 go build -trimpath`, `toolchain` directive pin in `go.mod`, `-buildvcs=false`, fixed `-ldflags` embedding only the release tag (arch §H.1). Two-runner byte-identical verification job (arch §H.1, PH-2 §6.3 criterion).
- **SLSA L3 provenance:** `slsa-framework/slsa-github-generator` Go builder, **pinned by full commit SHA**, DSPC-cleared (arch §H.2).
- **Sigstore keyless signing:** Fulcio OIDC-bound ephemeral cert + Rekor log + `cosign` blob signing; no long-lived release key (arch §H.3, §C.5).
- **CI hardening:** all Actions `@<full-sha>` + 14-day `/cool down`; `permissions: read-all` default, `id-token: write` confined to the environment-protected release job; branch protection + required review + signed commits + org 2FA; Dependabot bumps pass through the gate (dog-food) (arch §H.3, §C.8).
- **Release flow:** tag → matrix build (windows/macos/linux × amd64/arm64) → reproducibility check → provenance + cosign sign → GitHub Release w/ SHA-256 checksums → plugin-marketplace pin bump (arch §H.3).
- **Download site (CF Pages, static):** no backend, no cookies, no analytics by default; client-side consent checkbox (LMO D-1 text: license + AS-IS) — unchecked disables the download control, checked points at the immutable GitHub-Releases asset URL; the three-line verification recipe (`cosign verify-blob` / `slsa-verifier` / SHA-256) sits next to the download button (arch §E.1, §E.3). **No email gate, no signup, no funnel capture** (arch §E.1, Uri direct order). Subdomain = the one `PlaceholderSubdomain` constant in `registry/client.go` resolved to its real value.
- **`govulncheck` + lint-zero-warnings + `claude plugin validate`** wired blocking in CI (arch §K Security CI row).

**Definition of Done:**
- [ ] Tagged release produces win/mac/linux × amd64/arm64 binaries; two independent runners yield byte-identical artifacts or the release fails (arch §H.1).
- [ ] Each artifact carries SLSA L3 provenance verifiable with `slsa-verifier`, and a Sigstore signature verifiable with `cosign verify-blob` against the workflow OIDC identity (arch §E.3, §H.2/§H.3).
- [ ] All GitHub Actions pinned `@<full-sha>`, age ≥ 14 days, DSPC-recorded; release-job token least-privilege; no `pull_request_target` on untrusted code (arch §H.3).
- [ ] CF Pages site is fully static, checkbox-gated, zero-telemetry; download disabled until checkbox ticked; verification recipe present; `PlaceholderSubdomain` resolved (arch §E.1/§E.3).
- [ ] Windows SmartScreen guidance documented (v0 unsigned-Authenticode decision, arch §H.4 / §L-2).
- [ ] `govulncheck` clean; reproducibility + perf benchmark (arch §J, regressions > 20% fail) green in CI on all three OSes.
- [ ] **Public listing / OSS-repo gate respected:** the release pipeline is *built and dry-run-able*, but the public GitHub repo + marketplace listing do not go live until **PH-2 pentest pass + LMO E-items clear** (see §Cross-cutting).

**Maps to:** PRD FR-006 (distribution channels — direct-download + plugin marketplace at v0; pkg-managers deferred per §L-1), NFR-005 (cross-OS), NFR-006 (no-root). Arch §E.1–§E.5, §H.1–§H.4, §J, §K (Security CI), §C.5, §C.8, §L-1/§L-2/§L-7.

**Risk / dependency:** **U-domain item** — the real penbag.store subdomain + LMO D-1 domain/checkbox-text outcome must be resolved before the site goes live (LMO E-items). SLSA generator + Sigstore + Go-reproducibility facts already cited (arch Appendix S). Windows OV-cert cost is a `[NEEDS VERIFICATION]` CFA/LMO item if §L-2 is ever revisited.

---

## Chunk 5 — Internal pentest prep (PH-2 Stage 1)

**Goal:** prepare and execute the internal Stage-1 penetration test, wired to the PMA scope spec, feeding the non-skippable PH-2 security gate that unlocks any public/OSS release.

**Scope (per `knowledge/pma/specs/penrush/pentest/internal-stage1-scope-spec-v1.md` + arch §C):**
- Stand up the test harness for the seven STRIDE attack cases P-1…P-7 (arch §C.2): registry MITM, override-flow abuse, audit-log tampering, signed-binary forgery, plugin sandbox escape, insider/single-maintainer compromise, timing-side-channel + gate-check DoS.
- **Fuzz targets** (native Go `testing.F`, arch §K Fuzz row): #1 the command parser (TB1 bypass resistance — the highest-bypass-risk component, arch §A.5/§C.3), #2 registry-response decoding (TB2). Crasher corpus checked in; new crashers block merge.
- **Property tests** (arch §K Property row): (a) any single-byte mutation of any audit entry breaks `audit verify`; (b) NFR-007 — a blocked install leaves every manifest file byte-identical.
- **Threat-model doc** finalized verbatim from arch §C.1 TB1 framing (cooperative-but-careless = hard control; adversarial = cost-raiser; unparseable-install-fails-closed closes cheap evasions) — feeds LMO liability-disclosure (D-12) so marketing cannot overclaim.
- **E2E matrix** (arch §K E2E row): 8 ecosystems × {pass, block, override, unreachable, offline} × 3 OSes, full matrix green pre-release.
- Map each scope-spec test case to its arch §C.2 control row and its automated verifier; produce the PH-2 evidence package.

**Definition of Done:**
- [ ] Every P-1…P-7 case from the scope spec has a documented test/exercise and a pass/fail result mapped to its arch §C.2 control row.
- [ ] Fuzz targets #1/#2 run in CI with a seeded corpus; zero open crashers; new crashers block merge (arch §K).
- [ ] Property tests (audit-chain mutation, manifest-byte-identical-on-block) green per PR (arch §K, NFR-007).
- [ ] E2E install-command matrix green across 3 OSes (arch §K).
- [ ] Threat-model doc finalized and handed to LMO (D-12) with the honest TB1 limitation stated (arch §C.1).
- [ ] PH-2 evidence package assembled and routed to the pentest verdict gate (external pentest, $20K–35K target, separate D-11 dispatch per arch §X).
- [ ] **Gate outcome recorded:** PH-2 pass is the precondition that — together with LMO E-items — unlocks the public repo + marketplace listing + CF Pages go-live from chunk 4.

**Maps to:** PRD §12 (security gate), NFR-007 (no-manifest-mutation), arch §C (entire), §K (Fuzz/Property/E2E/Security-CI). Scope spec: `knowledge/pma/specs/penrush/pentest/internal-stage1-scope-spec-v1.md`. Consultation: `knowledge/pma/specs/penrush/dispatches/PENTEST-CONSULTATION-CTO-JUDGE.md`.

**Risk / dependency:** external pentest sourcing + budget is an **Uri/CFA decision** (`knowledge/pma/decisions/2026-05-26-penrush-pentest-sourcing.md`); internal-stage prep proceeds independently and is the input that makes the external engagement efficient. PH-2 is **non-compressible** (Uri 2026-05-25) — no chunk may skip ahead of it to a public release.

---

## Chunk 6 — Install-time remote-code-execution gate (FR-106, capability #3) — 🟡 v-next · PLAN ONLY · GATED

> **First content-analysis gate.** Ships **PenRUSH**'s first *fetch-payload-and-statically-scan* subsystem ("Gate 8") — the first gate that inspects package **contents** (install-lifecycle hooks), not just registry **metadata**. Strictly **post-launch v-next**: it does **not** block, gate, or alter the launched **v0.1.0**. Numbering continues the chunk sequence; it is not part of the v0 launch path (chunks 3–5).
>
> **🔴 BUILD GATE (binding — both must clear before any code):** Chunk-6 build starts **only after (a)** Uri approves the v-next architecture delta + this Build-Plan Chunk 6, **and (b)** the separate **Chunk-6 pentest-posture decision** (PH-2b internal-first-vs-external + budget). Until both clear: no `internal/payload`, no `internal/installscan`, no Gate 8, no v0 change. `git push` remains GODclaude-only.

**Goal:** add a new **Gate 8** that fetches the package payload, reads its install-lifecycle hooks, and statically detects a *fetch-remote-then-execute* pattern (FR-106) — behind the **unchanged** `gate.Engine`/`Verdict` seam, exactly like chunk 2's resolvers rode the `registry.Resolver` seam.

**Upstream:** PRD **v1.2 §5.7 FR-106** + §4.4 (`MD/DSPC-Product-PRD-v0.1.md`) · roadmap addendum **§4b** (`knowledge/pma/specs/penrush/roadmap-addendum-vnext-content-analysis-gates-v1.md`) · **v-next architecture delta** (`knowledge/cto/architecture/penrush-vnext-content-analysis-delta.md`) — the authoritative subsystem design for this chunk.

**Scope (per the architecture delta §V1–§V4):**
- **`internal/payload` (new)** — resolve the artifact-download URL from the metadata `internal/registry` already fetched (npm `dist.tarball` · PyPI `urls[].url` · crates download endpoint · RubyGems `.gem` url · Docker config-blob ref); **SSRF-validate** it (https-only + per-ecosystem host allowlist + private/loopback/link-local IP reject + off-allowlist-redirect reject); hardened fetch reusing the §D.1 posture; **bounded, in-memory, read-only** archive scan — **no disk write** (delta §V4.4). Stdlib only (`archive/tar`·`archive/zip`·`compress/gzip`·`compress/bzip2`·`io`·`net/http`·`net/url`·`net`).
- **`internal/installscan` (new)** — per-ecosystem lifecycle-hook locator (npm `package.json` scripts · PyPI `setup.py`+`.py` build hooks, `pyproject.toml` backend via bounded byte-scan · cargo `build.rs` · gem `extconf.rb`/`ext/**` by path-convention · Docker `RUN` from image-config `history[].created_by`) + a bounded **fetch-sink ∧ exec-sink** co-occurrence scanner; unparseable → **fail-closed**. Stdlib only (`encoding/json`·`regexp`·`strings`·`bytes`). **Never executes payload code** (delta §V4.9).
- **`internal/gate/gate8.go` (new)** — wires the above behind the **unchanged** `gate/gate.go` `Verdict`/`Engine`; emits **HIGH** `remote-code-on-install` (→ block) and **MEDIUM** `install-script-present` (→ advisory); Go modules → **`G8: n/a`** (never false-blocks). Short-circuits (no payload fetch) when a cheaper hard gate already blocks (delta §V1.2 — the 14-day age gate naturally defers heavy scans to survivors).
- **Zero-dep posture (held for v0 of FR-106):** all fetch/unpack/scan needs are Go stdlib; `pyproject.toml` (TOML) + gemspec (YAML) are **enrichment, deferred** — detection runs on text/JSON source files, not structured config (delta §V1.4). **IF** enrichment is later pursued, one DSPC-cleared parser per format under `/cool down` (≥14-day age) + `/lock file` (exact-pin+hash), recorded in `docs/dspc/<dep>.md` per arch §A.2.
- **Reuse, no new stores:** Gate-8 findings flow through the existing override store (mandatory reason, 30-day expiry, exact-key) and the SHA-256-chained audit log with credential redaction (FR-011); verdict cached per `{ecosystem,name,version,digest}` inside the §B.3 HMAC cache perimeter.
- **🔴 Own pentest scope (binding) — PH-2b:** because Chunk 6 fetches + parses **untrusted package payloads** (archive-bomb · zip-slip / path-traversal · symlink escape · SSRF · parser-DoS · nested-archive — a materially larger surface than metadata-only v0), it gets its **own** PH-2-style scope (cases PA-1…PA-9, delta §V4.10) **before it ships**. It **does NOT ride the v0 pentest** and never touches v0 (PRD §4.4 launch-firewall; addendum §5 cond. 3).

**Definition of Done:**
- [ ] `internal/payload` fetches + reads the 5 script-bearing ecosystems' archives; **decompression-bomb (uncompressed+count+per-entry caps) · zip-slip · symlink-reject · nested-depth-cap · SSRF-allowlist** defenses tested; **no disk write**; **never executes** payload code (delta §V4).
- [ ] `internal/installscan` locates lifecycle hooks per ecosystem (npm/pip incl. `pyproject.toml` backend/cargo/gem/docker) and flags fetch∧exec; benign install scripts → advisory only; Go → `n/a`.
- [ ] **All 8 FR-106 acceptance criteria green** (PRD §5.7): npm/pypi/cargo/gem/docker HIGH-block · benign `node-gyp rebuild` advisory · Go `G8: n/a` · unparseable fail-closed · honest-limit doc line shipped in user-facing docs.
- [ ] **Zero change** to `gate/gate.go` `Verdict`/`Engine` surface (Gate 8 rides the proven seam, like chunk 2); with Gate 8 disabled, behavior is byte-identical to v0.1.0.
- [ ] Recorded-fixture integration tests (**zero live calls in CI**); **two fuzz targets** — the install-script parser (highest bypass-risk) + the archive/decompression decoder; **property tests** — no-execution invariant (§V4.9), blocked-install-leaves-manifests-byte-identical (NFR-007), any parse failure → fail-closed.
- [ ] Latency budget honored: payload fetch only on install-like commands that reach Gate 8 and pass the metadata gates; verdict cached per artifact-version-digest; no-match/cached paths unchanged (arch §J; delta §V6).
- [ ] **PH-2b own-pentest evidence package** (PA-1…PA-9) assembled and passed **before any public shipment** — distinct from v0's PH-2.
- [ ] `go build ./...` exit 0; `go test ./...` PASS; `go vet ./...` clean; coverage ≥ 80% new files (CTO standard).

**Maps to:** PRD **v1.2 §5.7 FR-106** + §4.4 · roadmap addendum §4b · architecture delta §V1–§V9 (extends arch §A.6 new-module-behind-seam, §C new threat rows, §K fuzz/property/integration). Internal-DSPC twin of #3 (automate Gate 6/6b via SkillSpector): addendum §6, routed to GODclaude.

**Risk / dependency:** **two go-live gates** — (a) Uri approval of the delta + this chunk, (b) the Chunk-6 pentest-posture decision (PH-2b internal-first-vs-external + budget, same $15K–50K external band as v0's PH-2 per arch §X — CFA/Uri call). Zero-dep held for v0 (delta §V1.4). No external code dependency; the seam is proven (chunks 1–2). Endpoints re-verified against the fact-check rule at build time.

---

## Cross-cutting (spans chunks 2–5)

- **Test pyramid backfill:** chunk 1 landed unit tests on the core; the parity corpus (chunk 3), fuzz + property + E2E matrix (chunk 5), and per-ecosystem fixtures (chunk 2) complete arch §K. Coverage target ≥ 80% lines held per chunk (CTO standard).
- **Dog-fooding:** the **PenRUSH** repo runs under the internal DSPC hook + its own gate from the first commit; every new dependency (there should be none at runtime) requires a `docs/dspc/<dep>.md` record before its PR (arch §A.2).
- **Release gate (binding):** no public GitHub repo, no marketplace listing, no CF Pages go-live until **PH-2 pentest pass + LMO E-items clear**. Local commits and dry-run pipelines are fine; the internet boundary is gated. `git push` is GODclaude-only (PSS hard rule).
- **Naming:** `penrush` / `~/.penrush/` is ratified (arch §L-3); PMA updates PRD FR example text at the next PRD revision — a doc task, not a code task.

---

## Change log

| Version | Date | Change |
|---|---|---|
| v1.0 | 2026-06-16 | Initial build plan by **CTO**. Chunk 1 recorded DONE+green; chunks 2–5 specified with per-chunk DoD mapped to PRD FRs + architecture §A–§L and §K test strategy. Filed alongside the chunk-1 source. |
| v1.1 | 2026-07-13 | **CTO adds Chunk 6 (v-next, PLAN ONLY, GATED)** per Uri-authorized dispatch: FR-106 install-time remote-code-execution gate — the first fetch-payload + static-scan subsystem (Gate 8: `internal/payload` + `internal/installscan` + `gate8.go`), behind the unchanged `Verdict`/`Engine` seam. Per-ecosystem hook surface (npm/pip/cargo/gem/docker; Go = n/a); HIGH `remote-code-on-install`→block / MEDIUM `install-script-present`→advisory / unparseable→fail-closed. 🔴 Untrusted-payload hardening (decompression-bomb/zip-slip/symlink/SSRF/parser-DoS/no-execution) + **own PH-2b pentest scope**. Zero-dep held for v0 (stdlib archive/scan; TOML/YAML enrichment deferred). Header status updated to chunks 1–5 shipped + v0.1.0 launched. **Build gated on Uri approval + the Chunk-6 pentest-posture decision — no code.** Subsystem design: `knowledge/cto/architecture/penrush-vnext-content-analysis-delta.md`. |
