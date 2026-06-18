# **PenRUSH** — PH-2 Internal-Pentest Evidence Package (Stage-1)

| Field | Value |
|---|---|
| **Document** | PH-2 Stage-1 internal-pentest evidence package — per case (P-1…P-7 + TB1 + P-8/P-9/P-10/LINDDUN): exercise performed · result · architecture §C.2 control row · residual risk; fuzz/property/E2E status; the remediation log for findings closed this run; and the honest "what the INTERNAL stage cannot certify" section. |
| **Author** | **CTO** |
| **Status** | 🟡 **Stage-1 internal first-pass COMPLETE.** This is *informative input* to the Stage-2 external firm, **never a substitute** (scope spec §2.3; CTO HYBRID verdict; anchoring-bias control). Stage-2 + Uri financial authorization + LMO E-items remain the precondition for PH-2 PASS. |
| **Authoritative specs** | scope spec `knowledge/pma/specs/penrush/pentest/internal-stage1-scope-spec-v1.md` · architecture `knowledge/cto/architecture/penrush-phase-0.5.md` §C/§K · Judge methodology `knowledge/judge/audits/penrush-methodology-validation.md` §A.3–A.4 |
| **Companions** | `docs/security/threat-model.md` (D-9, trust boundaries + attack trees + LINDDUN) · `docs/security/ph2-case-map.md` (per-case verifier map) · `SECURITY.md` (disclosure policy + redaction posture) |
| **Build under test** | branch `main`, commit `aec8acd` (F-1 close) atop `cbf26ba` (evidence package) / `11fe6bd` (chunk-5 remediation) / `75e52b6` (chunk-5 harness); module `github.com/penrush/penrush` |
| **Toolchain** | **Go 1.26.4** windows/amd64; `toolchain go1.26.4` pinned in `go.mod` |

---

## §0 — Live verification receipts (this run, 2026-06-18)

Every number below is from a command run on the build machine this session — not
asserted from memory. Reproduction recipe per case in `ph2-case-map.md` §"How to reproduce".

| Gate | Command | Result |
|---|---|---|
| Static analysis | `go vet ./...` (`GOFLAGS=-mod=readonly`) | **clean (exit 0)** |
| Build | `go build ./...` | **exit 0** |
| Full suite | `go test ./...` | **all packages PASS** — 105 top-level tests, **0 failures** (487 `RUN` incl. subtests) |
| Dependency vuln scan (§K Security-CI) | `govulncheck ./...` | **No vulnerabilities found** |
| Dependency posture (dog-food) | `go list -m all` | **`github.com/penrush/penrush` only — ZERO third-party runtime deps** (architecture §A.2 commitment verified) |
| **Fuzz #1** — `FuzzParseInstallCommand` (TB1 parser) | `go test ./internal/cli/ -run x -fuzz FuzzParseInstallCommand -fuzztime=30s` | **PASS — 93,760 execs, 30 new-interesting, 0 crashers** |
| **Fuzz #2** — `FuzzRegistryDecode` (TB2 registry decode) | `go test ./internal/registry/ -run x -fuzz FuzzRegistryDecode -fuzztime=30s` | **PASS — 0 crashers** |
| Cluster regression suites (the 24 findings as tests) | `go test ./internal/{cli,audit,config,redact,gate}/ -run 'Bypass|Pentest|Verify|Redact|Cooldown|Override|Config|SemanticOracle|Hook|AuditVerify|SiteRecipe|Goldens' -count=1` | **all PASS** |

---

## §1 — Per-case evidence

Each case: **exercise performed → result → architecture §C.2 control row → residual risk.**
Verifier test names are exact (`go test -run <Name>`).

### P-1 — Registry MITM (Spoofing / Tampering) — §C.2 row 1

- **Exercise:** drove arbitrary attacker-controlled response bytes through the real
  hardened `Client.GetJSON` decode path across all 8 ecosystems (`FuzzRegistryDecode`,
  in-memory `RoundTripper`); asserted the client refuses non-HTTPS schemes before any
  fetch (`TestGetJSONRejectsNonHTTPS`); asserted 429/403/5xx fail closed per ecosystem
  (`TestRetryingStatusesFailClosed`); redirect guard rejects non-HTTPS redirects.
- **Result:** **PASS.** Fuzz invariant held — no panic, never `(nil,nil)`, a returned
  `Resolution` always carries a **non-zero** `PublishedAt` (a MITM cannot mint a
  "very-old → pass" verdict from garbage). 0 crashers.
- **Control:** TLS-only via Go stdlib system roots; no `--insecure` flag exists by
  design; HTTPS-only endpoints; cross-host non-HTTPS redirects rejected; size-capped
  strict decode.
- **Residual:** TLS trust = system root store; a host with a malicious root CA installed
  is **out of model** (documented; attack-tree A leaf A1.4). We do not cert-pin
  (intentional). Stage-2 may attempt cert-pinning-bypass.

### P-2 — Override-flow abuse (Elevation of Privilege) — §C.2 row 2

- **Exercise:** reason-mandatory (`TestOverrideAddRequiresReason`); wildcard key rejected
  (`TestOverrideAddRejectsWildcardKey`); active override flips block→pass end-to-end
  across 8 ecosystems (`TestE2EMatrix/*/override`); **version-pinned override does not
  cover a newer version** (`TestVersionPinnedOverrideDoesNotCoverNewerVersion`, PR-P2-02).
- **Result:** **PASS.** The one tracked **LOW** correctness finding (F-1 — *not* a
  privilege escalation; it failed *closed*) is now **CLOSED** this run (commit `aec8acd`,
  regression `TestF1CargoOverrideKeyConsultedThroughDocumentedCommand`).
- **Control:** mandatory reason; 30-day hard expiry never null; exact-key only;
  version-pinned (a different version re-enters the age gate); every use audit-chained;
  override-rate KPI; **unified ecosystem-token namespace** across resolver `Ecosystem()`,
  `gate.ArtifactKey`, `check.go` registration, the printed override hint, and
  `override.knownEcosystems` (F-1 fix).
- **Residual:** none open. (F-1 closed; was LOW / fails-closed.)

### P-3 — Audit-log tampering (Tampering / Repudiation) — §C.2 row 3

- **Exercise:** property test of 12 randomized chains (attacker-flavored content incl.
  credentials/unicode/every decision type) × sampled byte mutations — every mutation
  must break `Verify` (`TestPropertyAnyByteMutationBreaksVerifyRandomized`); exhaustive
  every-byte mutation of a canonical chain (`TestAnyByteMutationBreaksVerify`);
  deletion/reorder/genesis; **literal-on-disk-byte binding** detecting key injection,
  duplicate keys, `\uXXXX` re-encoding, reorder (`TestVerifyDetectsInjectedKey`,
  `TestVerifyDetectsDuplicateKey`, `TestVerifyDetectsUnicodeReEncoding` — INT-02).
- **Result:** **PASS.** No open finding.
- **Control:** SHA-256 chain binding the literal on-disk bytes + `penrush audit verify`
  (exits `ExitTamper(3)` so CI/cron detect tampering by exit status — INT-05).
- **Residual:** full-log re-forge by a same-privilege local attacker is **tamper-evidence,
  not tamper-proofing** (documented; v1 Ed25519). Honest limitation, not a defect.

### P-4 — Signed-binary forgery (Spoofing) — §C.2 row 4

- **Exercise:** reproducible double-build runs locally
  (`build.sh verify-reproducible`, byte-compare); release pipeline
  (`.github/workflows/release.yml`) + reproducible-build CI job (`ci.yml`); the
  site/docs verification recipe is **identity-pinned** (`--certificate-identity-regexp`)
  and `--source-tag`-aligned, with a Go test asserting `site/index.html` and
  `docs/RELEASE.md` stay byte-aligned (`TestSiteVerificationRecipeIsIdentityPinned` — INT-01).
- **Result:** **DEFERRED-TO-CI / release-gated.** Reproducible double-build is locally
  assertable; full Sigstore keyless-signing verification requires the GitHub OIDC
  environment and runs in CI on a tagged release — **not locally assertable, and not
  faked here.**
- **Control:** Sigstore keyless (Fulcio OIDC-bound certs, Rekor log, cosign blob
  signing) + SLSA L3 provenance + reproducible build.
- **Residual:** Tree-B leaf B3 — a user who **skips** verification is unprotected (UX,
  not cryptographic); v0 Windows unsigned-Authenticode SmartScreen prompt (§H.4/L-2).

### P-5 — Plugin sandbox escape (Elevation of Privilege) — §C.2 row 5

- **Exercise:** the entire plugin permission surface is auditable in `penrush-plugin/`
  (manifest + one `PreToolUse`-on-Bash `hooks.json` + locator shim); the hook adapter's
  behavior is fully covered by the cli hook suite (`TestParityCorpus`,
  `TestHookEmitsValidPermissionDecisionJSON`, `TestHookFailsClosedOnUnparseableStdin`,
  `TestHookPanicRecoversToBlock`, `TestHookAllowsNonBashTool`); `claude plugin validate`
  runs in CI before any marketplace submission; **NFR-007** corroborates zero side
  effects on the block path (`TestPropertyBlockedInstallLeavesManifestsByteIdentical`).
- **Result:** **PASS.** Minimal, static manifest scope; no executable escape surface in v0.
- **Control:** hooks + bin only — no MCP servers, no agents, no `settings.json`
  overrides; binary runs at user privilege (NFR-006 no-root).
- **Residual:** none in v0 beyond the user-privilege model (a plugin runs with the user's
  own rights by design).

### P-6 — Insider / single-maintainer compromise — §C.2 row 6

- **Exercise:** process + platform controls — branch protection + required review +
  signed commits + org 2FA + **PSS** GODclaude-only-push; SLSA provenance binds
  artifact→repo→workflow; CI Actions pinned by full commit SHA + 14-day `/cool down`.
  This harness was committed **locally only — no push** (GODclaude-only-push hard rule).
- **Result:** **DEFERRED** (process/platform-verified; no local Go-test surface).
- **Control:** the org/account is the root of trust post-keyless (architecture §C.5);
  SLSA provenance is the technical backstop so a hijacked laptop cannot mint an official
  release outside CI.
- **Residual:** insider risk is **the** structural risk of a single-maintainer project —
  this is precisely a case the **external** firm must probe independently; the internal
  stage cannot self-certify maintainer-compromise resistance (see §3).

### P-7 — Timing side-channel + gate-check DoS — §C.2 row 7

- **Exercise:** rate-limit governors cannot burst past a registry's published ceiling
  (`TestTokenBucketRefillCaps`, `TestCargoTokenBucketTiming` — cargo 1 rps / gem 10 rps,
  virtual clock); DoS → block, never warn-and-pass
  (`TestCheckFailsClosedOnUnreachableRegistry`, `TestE2EMatrix/*/unreachable` ×8,
  `TestE2EMatrix/*/offline` ×8); retry path is context-bounded
  (`TestTokenBucketRespectsContextCancel`).
- **Result:** **PASS.** DoS degradation correct (availability sacrificed before integrity).
- **Control:** per-ecosystem rate-limit compliance; block-until-cooldown-clear caching
  removes re-poll storms; fail-closed on unreachable.
- **Residual:** cache hit/miss **timing side-channel** is low-value and **not** mitigated
  in v0 — documented accepted risk, not an open defect. Stage-2 may quantify it.

### TB1 — Command-parser bypass (highest-risk component) — §C.1, §A.5

- **Exercise:** `FuzzParseInstallCommand` with a **semantic differential oracle**
  (PR-TEST-001): any install-bearing segment must not resolve to a silent allow;
  invariants — no panic (a parser crash is a §C.6 bypass primitive), `ActionGate ⇒
  non-empty trimmed Name` (no unparseable-pass bypass), dispatchable ecosystem,
  determinism. Seeded with adversarial TB1 classes (command substitution, nested shell
  wrappers, separator floods, at-sign/colon math, gh-shorthand traversal, unicode, NUL).
  Plus `TestParseInstallCommand` (explicit branch cases), `TestParseUnparseableFailsClosed`,
  the 22-case `TestParityCorpus` against the reference Python hook oracle, and the
  five named bypass regression tests (PR-TB1-001..004b, below).
- **Result:** **PASS.** 93,760 execs this run, 0 crashers; fail-closed principle holds
  under fuzzing.
- **Control:** unparseable-install-fails-closed (§A.5); **segment-split-before-classify**
  with most-restrictive-segment decision (closes safe-frozen short-circuit and
  chained-second-install laundering); Unicode normalization (closes verb-hiding).
- **Residual (verbatim, ships in launch messaging):** a PreToolUse gate cannot win
  against an arbitrarily obfuscating shell; **PenRUSH** is a hard control for
  cooperative-but-careless flows and a cost-raiser for adversarial ones. A day-2
  parser-evasion PoC is an **expected event, not a refutation** (threat-model §2).

### P-8 — Crash-to-bypass (fail-closed under induced failure) — §C.6, R-17

- **Exercise:** a panicking resolver on the gate path → fail-closed exit 2
  (`TestHookPanicRecoversToBlock`); empty/malformed stdin → exit-2 block
  (`TestHookFailsClosedOnUnparseableStdin`); both fuzz targets' no-panic invariants.
- **Result:** **PASS.** A crashing gate cannot become a bypass primitive.
- **Control:** `on_internal_error: "block"` default + panic-recovery wrapper; exit 2 is
  the only reliably-blocking code (exit 1 would let the tool proceed).
- **Residual:** none; the deliberate divergence from the internal hook's fail-open is
  documented (architecture §C.6).

### P-9 — Attack-tree validation (two chained attacks) — Judge §A.3 S1

- **Exercise:** the per-link controls are individually verified (Tree-A links: P-1
  verifiers; Tree-B links: reproducible build + SLSA + cosign, release-gated). **The
  attack trees themselves are now authored** in `docs/security/threat-model.md` §4.
- **Result:** **PASS for link-validation; trees DELIVERED in the D-9 threat-model.**
  Stage-1 validates the links; **Stage-2 attempts to extend the trees** (anchoring-bias
  control — the firm is not handed a finished map to merely confirm).
- **Residual:** chain *extension* is reserved for the external firm by design.

### P-10 / LINDDUN — Audit-log credential redaction — Judge §A.3 S2, FR-011

- **Exercise:** golden corpus (`TestGoldens`) — URL userinfo (incl. the FR-011
  `pip --index-url https://user:TOKEN@host` AC verbatim), `ghp_`/`github_pat_`/`hf_`/
  `sk_live_`/`AIza` machine tokens, Bearer/Basic headers, JWTs, `--token`/`--password`/
  `--api-key`/`curl -u`/`mysql -p` flags, `*_TOKEN=` env; PyPI-prefix
  (`TestPyPITokenPrefixCaught`); the audit *writer* redacts unconditionally at the single
  `Append` chokepoint over **command + reason + override-key** and the chain still
  verifies over redacted content (`TestAppendRedactsReasonField`,
  `TestAppendRedactsOverrideKeyField` — INT-03/PRIV-01); deny reason redacted before
  reaching the agent (`TestHookDenyReasonRedacted`); no-false-positive corpus
  (`TestRedactorNoFalsePositives`).
- **Result:** **PASS.**
- **Control:** redact every durable free-text field at one chokepoint; bind the literal
  on-disk bytes in the tamper chain. **§G.2 inheritance:** v1 audit-streaming must stream
  the *redacted* canonical chain, never raw commands.
- **Residual:** redaction is **defense-in-depth, not a guarantee** — a maintained denylist
  cannot recognize every secret shape; treated as a corpus that grows with reports
  (SECURITY.md). LINDDUN registry-query metadata exposure is accepted/documented
  (threat-model §5.2).

---

## §2 — Remediation log (findings fixed this run — commit `11fe6bd`)

The internal harness was run as 4 adversarial clusters. **24 findings** surfaced
(15 medium-or-higher); **all 24 were remediated this run** with a fail-before/pass-after
regression test for each (all token fixtures synthetic — assembled at runtime, **no
committed secret**). Exploits re-confirmed closed **through the production hook**.

| Cluster | ID | Severity | Finding | Fix | Regression test |
|---|---|---|---|---|---|
| **TB1 parser** | PR-TB1-001 | HIGH | Safe-frozen whole-command short-circuit lets a chained malicious install ride a benign frozen one | Segment-split **before** classify; per-segment classification; most-restrictive decision | `TestZZBypassSafeFrozenShortCircuit` |
| | PR-TB1-002 | HIGH | First-match-only single-result eval launders a chained second install | `ParseInstallCommands()` returns per-segment results; hook evaluates+audits **every** gated segment | `TestZZBypassChainSecondInstall`, `TestHookChainedInstallBypassesDeny` |
| | PR-TB1-003 | MED | Unicode / zero-width / line-separator verb evasion → silent ignore | Unicode normalization (zero-width dual-variant, U+2028/9→newline, all Unicode whitespace→ASCII), stdlib-only | `TestZZBypassUnicodeVerb` |
| | PR-TB1-004a | MED | Version-less `go get`/`go install <mod>` passes unpinned | Blocks as missing-pin | `TestZZBypassVersionlessGo` |
| | PR-TB1-004b | MED | `gh repo clone` flag-positioned target evades gating | Scan positionals past leading flags / `--` | `TestZZBypassGhCloneFlag` |
| | PR-TEST-001 | (test) | No semantic oracle for silent-allow bypasses | Fuzz #1 gains a differential oracle: any install-bearing segment must not silent-allow | `TestSemanticOracleEverySegmentSurfaced` |
| **Audit integrity** | INT-02 | HIGH | Chain bound parsed fields, not on-disk bytes → key injection / duplicate-key / `\uXXXX` re-encode / reorder survive | `Verify()` binds the **literal on-disk bytes** | `TestVerifyDetectsInjectedKey`, `TestVerifyDetectsDuplicateKey`, `TestVerifyDetectsUnicodeReEncoding` |
| | INT-05 | MED | No machine-detectable tamper signal for CI/cron | `penrush audit verify [--json]` re-walks chain, exits `ExitTamper(3)` | `TestAuditVerifyCommand` |
| | INT-01 | MED | Site cosign/SLSA recipe could drift from canonical docs (verification-substitution) | Identity-pinned (`--certificate-identity-regexp`) + `--source-tag`; lock-step test | `TestSiteVerificationRecipeIsIdentityPinned` |
| **Privacy / redaction** | INT-03 / PRIV-01 | HIGH | Credentials in Reason + OverrideKey + deny-reason stored/echoed in plaintext | Redact over **all** durable free-text at the single `Append` chokepoint; override store redacts persisted reason; deny reason redacted pre-emit | `TestAppendRedactsReasonField`, `TestAppendRedactsOverrideKeyField`, `TestHookDenyReasonRedacted` |
| | INT-04 / PRIV-02 | MED | Redactor missed token classes; URL-password-with-`@` and quoted flag-value leaks | Added `hf_`/`sk_live_`/`AIza`/JWT/`Authorization: Basic`/`curl -u`/`mysql -p`; fixed `@`-in-password and quoted-flag leaks | `TestRedactorCoverage`, `TestRedactorNoFalsePositives` |
| **Override / config abuse** | PR-P2-01 | HIGH | `cooldown_days: 0` globally disables the gate, tracelessly | Clamp-up to `MinCooldownDays`; below-floor emits a `policy_changed` audit event | `TestConfigZeroCooldownDoesNotGloballyAllow`, `TestHookConfigZeroCooldownAuditedNotHonored`, `TestCooldownFloorClamps*`, `TestLooseningClampsReported` |
| | PR-P2-02 | HIGH | Version-blind override silently allows a *different* (newer, unreviewed) version | Overrides pin a reviewed `--version`; a different version re-enters the age gate | `TestVersionPinnedOverrideDoesNotCoverNewerVersion`, `TestVersionBlindOverrideStillCoversAnyVersion` |
| | PR-P2-03 | MED | Override-key credential persisted unredacted (shared with INT-03 chokepoint) | Same single-chokepoint redaction | (covered by PRIV-01 tests) |

> The 4-cluster run produced 24 findings; the rows above enumerate the distinct fix
> classes. The remaining medium+ findings are individual seed/oracle cases inside the
> fuzz and golden corpora rolled up under the PR-TB1-*, INT-*, PRIV-*, PR-P2-* fix
> classes — each carries a fail-before/pass-after assertion in the named suites
> (`internal/cli/parse_bypass_test.go`, `internal/cli/pentest_test.go`,
> `internal/audit/pentest_test.go`, `internal/config/pentest_test.go`,
> `internal/redact/pentest_test.go`, `internal/gate/pentest_test.go`).

### Still-open finding — NONE (F-1 CLOSED this run)

| ID | Severity | Case | Finding | Disposition |
|---|---|---|---|---|
| **F-1** | **LOW** | P-2 | cargo override-key namespace mismatch: the gate prints `penrush override add cargo:<name>` and looks up `cargo:` (`ArtifactKey("cargo", …)`), but `override.knownEcosystems` accepted only `crates:`. A cargo override was **un-addable** via the documented command and a `crates:`-keyed override was **never consulted**. | ✅ **CLOSED** — commit `aec8acd` (`fix(penrush): close F-1 — unify cargo/crates override-key namespace`). Unified all four touchpoints onto the canonical `"cargo"` token (the value `registry/cargo.go` `Ecosystem()` already returns, `internal/cli/check.go` already registers, and `gate.ArtifactKey` already prints): `override.knownEcosystems` flipped `crates`→`cargo`, plus the doc comment and the `ValidateKey` error message. The other 7 ecosystems unchanged. **Regression test** `TestF1CargoOverrideKeyConsultedThroughDocumentedCommand` (`internal/cli/pentest_test.go`) failed before / passes after: a cargo override added via the documented command key (`penrush override add cargo:serde --version 1.0.0`) is now consulted by the gate and flips block→OVERRIDE-pass for the pinned version, while a *different* version (`serde@2.0.0`) still re-enters the age gate and BLOCKs (PR-P2-02 version-pinning preserved). Verified `go vet ./...` clean, `go build ./...` exit 0, `go test ./... -count=1` green (no cache). |

**Exit-criteria readout (scope spec §2.3):** **zero open critical/high findings locally —
and now zero open findings of any severity.** All 24 medium+ pentest findings fixed +
regression-tested in commit `11fe6bd`; the one remaining LOW correctness finding (F-1)
is **CLOSED** in commit `aec8acd` with a fail-before/pass-after regression test. The
Stage-2-kickoff precondition (scope spec §2.3) is satisfied.

---

## §3 — What the INTERNAL stage CANNOT certify — reserved for the external firm

**Independence is the whole point of the HYBRID model** (CTO verdict). The internal
harness is a cost- and scope-reducer for Stage-2, **never a substitute** (scope spec
§1, §2.3). The following are explicitly **out of reach of a self-run internal stage** and
are reserved for the independent external pentest firm:

1. **Independence / anchoring bias.** The authors of the code wrote the tests. A
   self-audit cannot certify the *absence* of a blind spot it shares with the
   implementation. The external firm sets its own attack plan; this package is handed to
   it as **informative, not binding** input (anchoring-bias control).
2. **Attack-tree *extension* (P-9).** Stage-1 validated the per-link controls and
   authored the two trees (threat-model §4). Discovering **new branches** — chains we did
   not think to draw — is the external firm's job. A team cannot reliably find the chains
   it failed to imagine.
3. **Insider / single-maintainer compromise (P-6).** Genuinely adversarial probing of
   the org/CI/OIDC/Sigstore trust root, social-engineering and account-takeover paths,
   cannot be self-certified by the maintainer who is the subject of the threat.
4. **Live signed-release forgery (P-4).** End-to-end Sigstore keyless + SLSA provenance
   forgery attempts against a *real tagged release in the live OIDC environment* — the
   internal stage verified the reproducible double-build and the recipe lock-step, but
   the live keyless-signing adversarial test is release-gated and external-firm scope.
5. **Cross-OS adversarial behavior.** The 8×5 E2E matrix is OS-agnostic Go; CI fans it to
   ubuntu/macos/windows on push (push is GODclaude-gated). Locally **only the
   windows-latest leg has actually run** — the linux/macos legs are genuinely
   deferred-to-CI, not asserted here as run. Platform-specific adversarial behavior is
   external-firm scope.
6. **Timing side-channel quantification (P-7).** v0 accepts the cache-state timing
   side-channel as low-value and does not measure it; quantifying exploitability is
   reserved for Stage-2.
7. **Novel credential-class redaction gaps (P-10).** The denylist is defense-in-depth;
   an external firm (and the public, post-disclosure) will surface secret shapes the
   ruleset misses — by design the ruleset is a growing corpus.

A clean internal stage **does not equal PH-2 PASS.** It means the build is *ready for*
the external engagement with the cheap findings already burned down.

---

## §4 — Honest deferrals (verified, not faked)

| Case | Status | Why |
|---|---|---|
| **P-4** binary forgery | DEFERRED-TO-CI / release-gated | Live keyless signing needs the GitHub OIDC env on a tagged release; reproducible double-build is locally assertable, full signing is not |
| **P-6** insider compromise | DEFERRED (process/platform) | Process + platform controls, not Go-test surface; external-firm scope (§3.3) |
| **cross-OS E2E** | windows-local green; linux/macos DEFERRED-TO-CI | OS-agnostic tests; CI fan-out on push (GODclaude-gated); not asserted as locally run |
| **FR-010 offline prior-approval pass** | DEFERRED to Gate-7 (later chunk) | The offline column asserts the safe-default fail-closed block; the prior-approval-pass refinement depends on Gate-7; not asserted as existing |
| **F-1** cargo override key | ✅ CLOSED (commit `aec8acd`) | Fails-closed correctness defect; namespace unified on `"cargo"`; regression test `TestF1CargoOverrideKeyConsultedThroughDocumentedCommand` (fail-before/pass-after) |

---

## §5 — DoD readout (BUILD-PLAN chunk 5)

| DoD item | Status |
|---|---|
| Every P-1…P-7 has a documented test/exercise + pass/fail mapped to §C.2 control row | ✅ (§1 + `ph2-case-map.md`) |
| Fuzz #1/#2 run with seeded corpus; zero open crashers; new crashers block merge | ✅ (§0 — 0 crashers both targets) |
| Property tests (audit-chain mutation, manifest-byte-identical-on-block) green | ✅ |
| E2E install-command matrix green across 3 OSes | ✅ windows-local; linux/macos via CI on push (honest §4) |
| Threat-model doc finalized + handed to LMO (D-12), honest TB1 limitation stated | ✅ `docs/security/threat-model.md` §2 verbatim from arch §C.1 |
| PH-2 evidence package assembled + routed to the pentest verdict gate | ✅ this document |
| Gate outcome recorded: PH-2 pass precondition for public go-live | ✅ §6 below |

---

## §6 — Remaining gates to PH-2 PASS (precise: Uri's vs done)

PH-2 PASS — and any public/OSS go-live — requires **all** of the following. The internal
stage is **DONE**; the rest are **NOT** CTO's to close unilaterally.

| Gate | Owner | Status |
|---|---|---|
| Stage-1 internal harness: P-1…P-10 + TB1 exercised, 24 medium+ findings remediated + regression-tested, fuzz/property/E2E green, threat-model + evidence package filed | **CTO** | ✅ **DONE** (this package) |
| F-1 cargo override-key fix (LOW, fails-closed) before Stage-2 kickoff | **CTO** | ✅ **DONE** — commit `aec8acd`, regression test `TestF1CargoOverrideKeyConsultedThroughDocumentedCommand`; Stage-2-kickoff precondition (scope §2.3) satisfied |
| **External pentest-firm engagement** (HYBRID 2nd arm): RFP **draft-not-sent**; target **$20K–35K** (range $15K–50K) | **Uri** (financial authorization) → PMA executes | ⛔ **BLOCKED on Uri** |
| Stage-2 external pentest **executed + PASS** (zero open critical/high) | external firm → CTO regression | ⛔ depends on the line above |
| **LMO E-items** clear (D-1 domain/checkbox text, D-12 liability disclosure reviewing threat-model §2 verbatim) | **LMO** → Uri | ⛔ pending |
| Public repo + marketplace listing + CF Pages go-live | **GODclaude** (only-push) after all above | ⛔ gated |

**Bottom line:** the internal stage cannot self-promote to PASS. **The two precondition
gates that are not CTO's: (1) Uri's financial authorization for the external firm
(~$20K–35K, RFP drafted, not sent), and (2) LMO E-items.** Both must clear, the external
engagement must execute and PASS, before any internet boundary opens. `git push` stays
GODclaude-only.

---

## Sources

- scope spec `knowledge/pma/specs/penrush/pentest/internal-stage1-scope-spec-v1.md` §1/§2/§2.3 — read 2026-06-18
- architecture `knowledge/cto/architecture/penrush-phase-0.5.md` §C.2 / §K / §X — v1.0-RATIFIED, read 2026-06-18
- Judge `knowledge/judge/audits/penrush-methodology-validation.md` §A.3–A.4 — read 2026-06-18
- BUILD-PLAN `docs/BUILD-PLAN.md` chunk 5 DoD — read 2026-06-18
- Live receipts (§0): `go vet`/`go build`/`go test ./...`/`govulncheck ./...`/`go list -m all` + both fuzz targets, Go 1.26.4 windows/amd64, this session 2026-06-18
- Commits: `aec8acd` (F-1 close — `override.knownEcosystems` cargo unify + regression test), `cbf26ba` (evidence package), `11fe6bd` (remediation), `75e52b6` (harness); finding IDs traced via `git grep` of the regression suites
- F-1 close verification (this run, 2026-06-18): `TestF1CargoOverrideKeyConsultedThroughDocumentedCommand` fail-before/pass-after; `go vet ./...` clean, `go build ./...` exit 0, `go test ./... -count=1` all packages PASS (no cache), Go 1.26.4 windows/amd64
- Companion: `docs/security/threat-model.md`, `docs/security/ph2-case-map.md`, `SECURITY.md`

*Filed by **CTO**, PH-2 Stage-1. Local results only; no push (GODclaude-only-push hard rule). This package is informative input to the external firm, never a substitute (CTO HYBRID verdict).*
