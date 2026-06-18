# **PenRUSH** — PH-2 Pentest Case Map (Stage-1 Internal Harness)

| Field | Value |
|---|---|
| **Document** | P-1…P-10 + TB1 case map — each STRIDE attack → architecture §C.2 control row → the automated verifier that exercises it → current LOCAL pass/fail |
| **Author** | **CTO** (chunk-5 security test harness) |
| **Status** | 🟡 Stage-1 internal first-pass. Stage-2 external engagement is the binding gate (scope spec §2.3); this map is *informative input* to the external firm, never a substitute (CTO HYBRID verdict, anchoring-bias control). |
| **Authoritative specs** | scope spec `knowledge/pma/specs/penrush/pentest/internal-stage1-scope-spec-v1.md` · architecture `knowledge/cto/architecture/penrush-phase-0.5.md` §C.2 + §K · Judge methodology `knowledge/judge/audits/penrush-methodology-validation.md` §A.3–A.4 |
| **Harness scope (this chunk)** | Fuzz #1 (parser/TB1) · fuzz #2 (registry decode/TB2) · property tests (audit-chain integrity; NFR-007 no-side-effect-on-block) · the 8×5 E2E matrix · the existing chunk-1..4 unit/integration/parity suites. Live-binary forgery (P-4) and CI/build-pipeline controls (P-6) are verified by the release pipeline + CI jobs, not by Go unit tests — noted honestly per row. |
| **How to reproduce** | `go vet ./...` · `go build ./...` · `go test ./...` (all green locally) · fuzz: `go test ./internal/cli/ -run x -fuzz FuzzParseInstallCommand -fuzztime=30s` and `go test ./internal/registry/ -run x -fuzz FuzzRegistryDecode -fuzztime=30s` |

---

## Reading guide

- **Control row** is the row in architecture §C.2 (the STRIDE first-pass table) the case maps to.
- **Verifier** names the Go test / fuzz target / pipeline job that exercises the control. Test names are exact (`go test -run <Name>`).
- **Local pass/fail** is the result on the build machine (Windows, Go 1.26.4) as of this chunk. Cross-OS results are produced by CI on push (the same `go test ./...` runs on ubuntu/macos/windows-latest, `.github/workflows/ci.yml` `build-test` job) — see the honesty note under the E2E matrix; this column does **not** claim cross-OS results that have not run.

---

## P-1 — Registry MITM (Spoofing / Tampering)

- **Control (§C.2 row 1):** TLS-only via Go stdlib system roots; no `--insecure` flag exists by design; HTTPS-only endpoints; cross-host redirects to non-HTTPS rejected; responses schema-validated/size-capped/strict-decoded before use.
- **Verifiers:**
  - `TestGetJSONRejectsNonHTTPS` (registry) — the client refuses `http://`, `ftp://`, scheme-less, and empty URLs before any fetch. **Local: PASS.**
  - `FuzzRegistryDecode` (registry) — arbitrary attacker-controlled response bytes through the real hardened `Client.GetJSON` decode path × all 8 ecosystems; invariants: no panic, never `(nil,nil)`, a returned `Resolution` always carries a **non-zero** `PublishedAt` (a MITM cannot mint a "very old → pass" verdict from garbage). 30s bounded run: **0 crashers, PASS.** Checked-in seed corpus: `internal/registry/testdata/fuzz/FuzzRegistryDecode/` (zero-time strings, all-nulls, wrong-types, far-future time, raw garbage bytes).
  - `TestRetryingStatusesFailClosed` (registry) — 429/403/5xx on every ecosystem → fail-closed error, never a `Resolution`. **Local: PASS.**
  - Redirect guard: `Client.CheckRedirect` rejects non-HTTPS redirects (exercised in the client construction; integration-covered by the per-ecosystem httptest TLS suites). **Local: PASS.**
- **Honest residual:** TLS trust is the system root store; a host with a malicious root CA installed is out of model (documented, §C.1 posture). Stage-2 may attempt cert-pinning-bypass; we do not pin (intentional, system-roots).
- **Local verdict: PASS** (no open finding).

## P-2 — Override-flow abuse (Elevation of Privilege)

- **Control (§C.2 row 2):** mandatory reason; 30-day hard expiry, never null; exact-key only (no wildcards); every use audit-chained; override-rate KPI; v1 team approval.
- **Verifiers:**
  - `TestOverrideAddRequiresReason` — reason mandatory (FR-004). **PASS.**
  - `TestOverrideAddRejectsWildcardKey` — `npm:*` rejected (§C.4). **PASS.**
  - `TestOverrideAddThenCheckPasses` / `TestOverrideAddOrderIndependent` — an active override flips a block to `OverrideUsed`; CLI parsing is order-independent. **PASS.**
  - `TestE2EMatrix/*/override` (8 cells) — an in-store override at the engine's lookup key flips a fresh-block / approval-gate to a pass, end-to-end, across all 8 ecosystems. **PASS.**
- **Open finding (filed, LOW/cosmetic-but-real):** cargo's override key namespace mismatch — the gate prints `penrush override add cargo:<name>` but the override validator only accepts `crates:` (the engine looks up `cargo:`). A cargo override added via the documented CLI command is rejected; one added under `crates:` is never consulted. Tracked separately (see §"Open findings"). Not a privilege-escalation (it fails *closed* — overrides are harder, not easier), so not critical/high; but it is a correctness defect in a trust tool and must be fixed before Stage-2.
- **Local verdict: PASS with one tracked LOW correctness finding** (no critical/high).

## P-3 — Audit-log tampering (Tampering / Repudiation)

- **Control (§C.2 row 3):** SHA-256 hash chain + `audit verify`; any byte mutation, deletion, insertion, or reorder of a prior entry breaks verification. Honest limitation documented (full-log re-forge by a same-privilege local attacker is out of scope for tamper-*proofing*; v1 Ed25519).
- **Verifiers:**
  - `TestPropertyAnyByteMutationBreaksVerifyRandomized` (audit) — **property test:** 12 randomized chains (lengths 1–6, attacker-flavored content incl. credentials/unicode/every decision type) × sampled byte positions per line; every mutation must break `Verify`. **PASS.**
  - `TestAnyByteMutationBreaksVerify` (audit) — exhaustive every-byte mutation of a canonical 3-entry chain. **PASS.**
  - `TestDeletionBreaksVerify`, `TestReorderBreaksVerify`, `TestSeqAndGenesis`, `TestChainAppendAndVerify`. **PASS.**
- **LINDDUN-lite tie-in (P-10):** the chained log durably stores the command string → credential-redaction is mandatory at write time; see P-10.
- **Local verdict: PASS** (no open finding; honest limitation is documented, not a defect).

## P-4 — Signed-binary forgery (Spoofing)

- **Control (§C.2 row 4):** Sigstore keyless — Fulcio short-lived certs bound to the GitHub Actions OIDC identity; Rekor transparency log; cosign blob signing; SLSA L3 provenance.
- **Verifiers:** the release pipeline (`.github/workflows/release.yml`) + reproducible-build proof job (`ci.yml` `reproducible-build`, two-runner byte-identical via `build.sh verify-reproducible`). These are **pipeline/CI controls, not Go unit tests** — stated honestly. The provenance/cosign verification recipe ships in `docs/RELEASE.md` (the "verify before trust" three-line recipe).
- **Local status:** the reproducible double-build runs locally (`build.sh verify-reproducible`, `_rep1.exe`/`_rep2.exe` byte-compare). Full keyless-signing verification requires the GitHub OIDC environment and runs **in CI on a tagged release**, which is gated behind the PH-2/LMO release boundary — **DEFERRED-TO-CI / release-gated, not locally assertable, and not faked here.**
- **Local verdict: DEFERRED** (pipeline-verified, release-gated; no local finding).

## P-5 — Plugin sandbox escape (Elevation of Privilege)

- **Control (§C.2 row 5):** minimal plugin scope — `hooks/hooks.json` (one `PreToolUse` matcher on Bash) + `bin/` PATH only; no MCP servers, no agents, no `settings.json` overrides; binary runs at user privilege, requests nothing more (NFR-006 no-root).
- **Verifiers:**
  - Plugin manifest surface is auditable in `penrush-plugin/` (the whole permission surface is the manifest + hooks.json + the locator shim). `claude plugin validate` runs in CI before any marketplace submission.
  - The hook adapter's behavior is fully covered by the `cli` hook suite (`TestParityCorpus`, `TestHookEmitsValidPermissionDecisionJSON`, `TestHookFailsClosedOnUnparseableStdin`, `TestHookPanicRecoversToBlock`, `TestHookAllowsNonBashTool`, `TestHookUsage`) — the adapter never reads/writes outside stdin → registries → `~/.penrush/`.
  - `TestPropertyBlockedInstallLeavesManifestsByteIdentical` (NFR-007) corroborates: the gate has **zero side effects on the project tree** on the block path — there is no write-primitive to aim at the host (see P-8).
- **Local verdict: PASS** (manifest scope is minimal and static; no executable escape surface in v0; `claude plugin validate` is the CI gate).

## P-6 — Insider / single-maintainer compromise (Spoofing / Tampering / Repudiation)

- **Control (§C.2 row 6):** branch protection + required review; signed commits; org-wide 2FA; **PSS** GODclaude-only-push rule; SLSA provenance binds artifact→repo→workflow so a hijacked laptop cannot mint an "official" release outside CI.
- **Verifiers:** these are **process + platform controls**, not Go tests — stated honestly. The push chokepoint is enforced by the GODclaude-only-push hard rule (this harness was committed locally only; **no push** per the rule). SLSA provenance + reproducible-build are the technical backstops (see P-4). CI Actions are pinned by full commit SHA + 14-day cool-down (`ci.yml`/`release.yml` comments record the resolved dates).
- **Local status:** harness committed **locally only**; push is GODclaude-gated. No local Go-test surface.
- **Local verdict: DEFERRED** (process/platform-verified; no local finding).

## P-7 — Timing side-channel + gate-check DoS (Information Disclosure / DoS)

- **Control (§C.2 row 7):** timing — cache-state inference is low-value (accepted risk v0, documented); DoS — local request coalescing, registry rate-limit compliance, block-until-cooldown-clear caching removes re-poll storms; a DoS'd registry degrades to fail-closed (availability sacrificed before integrity, NFR-002).
- **Verifiers:**
  - Rate-limit governors: `TestTokenBucketRefillCaps`, `TestTokenBucketRespectsContextCancel`, `TestCargoTokenBucketTiming` (cargo 1 rps, gem 10 rps — the client cannot burst past a registry's published ceiling). **PASS.**
  - Fail-closed-on-unreachable (DoS → block, never warn-and-pass): `TestCheckFailsClosedOnUnreachableRegistry`, `TestRetryingStatusesFailClosed`, `TestE2EMatrix/*/unreachable` (8 cells), `TestE2EMatrix/*/offline` (8 cells). **PASS.**
  - The retry path is context-bounded (`GetJSON` backoff is `select`-ed against `ctx.Done()`), proven by `TestTokenBucketRespectsContextCancel` and the bounded fuzz runs.
- **Honest residual (accepted v0):** the cache hit/miss timing side-channel is documented as low-value and **not** mitigated in v0 (§C.2 row 7). Stated, not hidden; Stage-2 may quantify it.
- **Local verdict: PASS** (DoS degradation correct; timing residual is a documented accepted risk, not an open defect).

---

## TB1 — Command-parser bypass (the highest-risk component)

- **Trust boundary §C.1:** the shell command string is UNTRUSTED; in an agent workflow it may be adversarial. The unparseable-install-fails-closed principle (§A.5) closes the cheap evasions; the parser gets the fuzz budget.
- **Verifiers:**
  - `FuzzParseInstallCommand` (cli) — invariants: no panic (a parser crash is a §C.6 bypass primitive), Action always in range, **ActionGate ⇒ non-empty trimmed Name** (no unparseable-pass bypass), ActionGate names only a dispatchable ecosystem, deterministic. Seeded with adversarial TB1 classes (command substitution, nested shell wrappers, separator floods, at-sign/colon math, gh-shorthand traversal, unicode, NUL bytes). **30s bounded run: 176,390 execs, 200 new-interesting inputs, 0 crashers, PASS.** Checked-in seed corpus: `internal/cli/testdata/fuzz/FuzzParseInstallCommand/`.
  - `TestParseInstallCommand` (29 explicit branch cases) + `TestParseUnparseableFailsClosed` + `TestStripShellWrapper` + the 22-case `TestParityCorpus` against the reference Python hook oracle. **PASS.**
- **Honest residual (§C.1 posture, ships in launch messaging per Judge/CMSD constraint):** a PreToolUse gate cannot win against an arbitrarily obfuscating shell; PenRUSH is a hard control for cooperative-but-careless flows and a cost-raiser for adversarial ones. A day-2 parser-evasion PoC is an expected event, not a refutation.
- **Local verdict: PASS** (no crashers; fail-closed principle holds under fuzzing).

## P-8 — Crash-to-bypass (fail-closed under induced failure)

- **Control (§C.6, R-17):** `on_internal_error: "block"` default; the hook adapter wraps the whole run in panic-recovery that converts any internal failure into an explicit block; exit 2 is the only reliably-blocking code (exit 1 would let the tool proceed).
- **Verifiers:**
  - `TestHookPanicRecoversToBlock` (cli) — a panicking resolver on the gate path → fail-closed exit 2, not a silent bypass. **PASS.**
  - `TestHookFailsClosedOnUnparseableStdin` (cli) — empty/malformed stdin → exit-2 block (a deliberate divergence from the reference hook's fail-open). **PASS.**
  - `FuzzParseInstallCommand` no-panic invariant + `FuzzRegistryDecode` no-panic invariant — the two crash-prone surfaces cannot be crashed into a bypass. **PASS.**
- **Local verdict: PASS.**

## P-9 — Attack-tree validation (two chained attacks)

- **Scope (Judge §A.3 Supplement 1):** the registry-MITM chain (P-1 links) and the signed-binary-forgery chain (P-4 CI/OIDC/Sigstore links). D-9 threat-model doc must CONTAIN the trees; Stage-1 validates the per-link controls; Stage-2 attempts to extend them.
- **Status:** the per-link controls are individually verified (P-1 chain links: `TestGetJSONRejectsNonHTTPS`, `FuzzRegistryDecode`, `TestRetryingStatusesFailClosed`; P-4 chain links: reproducible build + SLSA + cosign, release-gated). **The attack-TREE document itself is a D-9 deliverable (threat-model doc), not a chunk-5 harness artifact** — flagged honestly: this harness validates the links, it does not author the trees. **DEFERRED to D-9 threat-model.**

## P-10 — LINDDUN-lite data-disclosure (audit-log credential redaction)

- **Control (Judge §A.3 Supplement 2 + §A.4; FR-011):** the audit log durably stores the command string; install commands embed credentials; redaction is mandatory at write time and no call path may bypass it.
- **Verifiers:**
  - `TestGoldens` (redact) — golden corpus: URL userinfo (incl. the FR-011 `pip --index-url https://user:TOKEN@host` AC verbatim), GitHub PAT prefixes (`ghp_`/`github_pat_`), npm/PyPI/GitLab/Slack/AWS tokens, Bearer headers, `--token/--password/--api-key` flags, `*_TOKEN=` env assignments. **PASS.**
  - `TestPyPITokenPrefixCaught` (redact). **PASS.**
  - `TestAppendRedactsCommand` (audit) — the audit *writer* redacts unconditionally; a caller passing a raw credentialed command cannot get plaintext stored, and the chain still verifies over the redacted content. **PASS.**
  - `TestPropertyAnyByteMutationBreaksVerifyRandomized` includes credentialed commands in its randomized entries (redacted on write), corroborating redaction-then-chain integrity.
- **§G.2 inheritance note:** the v1 audit-streaming seam inherits this requirement (it must stream the *redacted* canonical chain, never raw commands) — recorded in the architecture; out of scope for v0 code.
- **Local verdict: PASS.**

---

## Summary table

| Case | §C.2 row / source | Primary verifier(s) | Local |
|---|---|---|---|
| **P-1** registry MITM | row 1 | `TestGetJSONRejectsNonHTTPS`, `FuzzRegistryDecode`, `TestRetryingStatusesFailClosed` | **PASS** |
| **P-2** override abuse | row 2 | override unit suite, `TestE2EMatrix/*/override` | **PASS** (+1 LOW cargo-key finding) |
| **P-3** audit tampering | row 3 | `TestPropertyAnyByteMutationBreaksVerifyRandomized`, `TestAnyByteMutationBreaksVerify`, deletion/reorder | **PASS** |
| **P-4** binary forgery | row 4 | release pipeline + reproducible-build + SLSA/cosign | **DEFERRED** (release-gated) |
| **P-5** plugin escape | row 5 | minimal manifest + hook suite + NFR-007 no-side-effect | **PASS** |
| **P-6** insider compromise | row 6 | branch protection + GODclaude-only-push + SLSA provenance | **DEFERRED** (process/platform) |
| **P-7** timing + DoS | row 7 | token-bucket suite, fail-closed/unreachable/offline cells | **PASS** (timing residual accepted) |
| **TB1** parser bypass | §C.1, §A.5 | `FuzzParseInstallCommand`, parity corpus, parse suite | **PASS** |
| **P-8** crash-to-bypass | §C.6, R-17 | `TestHookPanicRecoversToBlock`, `TestHookFailsClosedOnUnparseableStdin`, fuzz no-panic | **PASS** |
| **P-9** attack-tree validation | Judge §A.3 S1 | per-link controls verified; tree doc is D-9 | **DEFERRED** (D-9 threat-model) |
| **P-10** LINDDUN-lite redaction | Judge §A.3 S2, FR-011 | `TestGoldens`, `TestAppendRedactsCommand` | **PASS** |

**Exit-criteria readout (scope spec §2.3):** zero open critical/high findings locally. Open findings: one **LOW** correctness defect (P-2 cargo override key namespace mismatch), tracked below. Three cases (**P-4, P-6, P-9**) are honestly **DEFERRED** — two to release-gated pipeline/process controls, one to the D-9 threat-model document — not silently skipped.

---

## Open findings

| ID | Severity | Case | Finding | Disposition |
|---|---|---|---|---|
| F-1 | LOW | P-2 | cargo override key mismatch: gate prints `override add cargo:<name>`; validator accepts only `crates:`; engine looks up `cargo:`. A cargo override is un-addable via the documented path and `crates:`-keyed overrides are never consulted. Fails closed (overrides harder, not easier) → not critical/high. | Fix before Stage-2: unify the cargo/crates key namespace across `override.knownEcosystems`, the gate `ArtifactKey`, and the printed hint. Add a regression test. |

---

## E2E matrix — cross-OS honesty note

The 8×5 matrix (`TestE2EMatrix`, 40 cells) and every other test in this harness are ordinary `go test` cases with no platform-specific code. The CI workflow's `build-test` job already runs `go test ./...` on **ubuntu-latest, macos-latest, and windows-latest** on every push, so the full 3×40 = 120-cell cross-OS execution happens **in CI after push** (push is GODclaude-only, PH-2-gated). **Locally only the windows-latest leg has actually run** — the linux/macos legs are genuinely deferred-to-CI, not asserted here as if they had run. There is no per-OS skip because the matrix is OS-agnostic; the Windows-local green + the CI fan-out together cover all three.

**MCP exception (honest):** the `mcp/pass` cell correctly **BLOCKS** — an MCP add is always approval-gated (§D.9), so an unattended pass state does not exist for it. The matrix encodes this as an exception (asserting the absence of a natural pass) rather than skipping the cell.

**Offline column (honest deferral):** the `offline` column currently asserts the safe-default fail-closed **block** for all 8 ecosystems (no network = unverifiable = block). The FR-010 *refinement* — pass artifacts carrying a Gate-7 prior-approval record while blocking everything else — depends on Gate 7 (prior-install), a **later-chunk gate** (gate.go: "G2-G7 land in later chunks"). It is **not** asserted here as if it existed; the override column already proves the pass-an-approved-artifact-without-network mechanic that Gate-7 will generalize.

---

*Filed by **CTO**, chunk-5 security test harness. Sources: scope spec, architecture §C.2/§K, Judge §A.3–A.4 (all read this chunk). Local results from `go test ./...` on Go 1.26.4 / Windows. No push (GODclaude-only-push hard rule).*
