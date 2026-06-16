# **PenRUSH** — Build Plan (chunks 2–N)

| Field | Value |
|---|---|
| **Product** | **PenRUSH** (internal codename: DSPC) — *"don't rush to download"* |
| **Document** | D-7 incremental build roadmap — chunk-by-chunk Definition of Done |
| **Status** | Living plan. Chunk 1 ✅ DONE + green. Chunks 2–5 specified below. |
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

## Chunk 2 — Remaining 5 ecosystems (cargo · gem · go · docker · mcp)

**Goal:** complete PRD §5.4 / arch §A.6 eight-ecosystem coverage by adding five `Resolver` implementations behind the *unchanged* `registry.Resolver` interface and the *unchanged* `gate.Engine` — proving the §A.6 "one module + one parser rule + fixtures, no engine change" claim.

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
