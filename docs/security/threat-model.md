# **PenRUSH** — Threat Model (D-9, finalized)

| Field | Value |
|---|---|
| **Document** | PH-2 D-9 threat-model — trust boundaries, STRIDE-per-element, two attack trees, LINDDUN-lite privacy pass, and the honest TB1 capability statement |
| **Author** | **CTO** |
| **Status** | 🟢 Finalized. The TB1 capability framing (§2) is **verbatim from architecture §C.1** and is the binding input to **LMO D-12** (liability disclosure) so launch messaging cannot overclaim. |
| **Authoritative upstream** | architecture `knowledge/cto/architecture/penrush-phase-0.5.md` §C (security architecture) · scope spec `knowledge/pma/specs/penrush/pentest/internal-stage1-scope-spec-v1.md` §2.2 (P-9 attack trees, P-10 LINDDUN) · Judge methodology `knowledge/judge/audits/penrush-methodology-validation.md` §A.3–A.4 (attack-tree + LINDDUN-lite supplements + audit-log credential-redaction FR) |
| **Framework** | **STRIDE** as the spine (Judge §A.2 verdict: SOUND) + two bounded supplements: **attack trees** (Schneier 1999) for the two chained attacks, **LINDDUN-lite** over local stores + registry-query metadata |
| **Companion** | Evidence that each control below is exercised: `docs/security/ph2-evidence-package.md` and `docs/security/ph2-case-map.md` |

---

## §1 — Trust boundaries (architecture §C.1)

```
 TB1: agent/user shell ──▶ penrush binary        (command string is UNTRUSTED)
 TB2: penrush ──▶ registries over TLS            (responses are UNTRUSTED)
 TB3: penrush ──▶ local stores (~/.penrush)      (same-privilege attacker assumed)
 TB4: Claude Code runtime ──▶ plugin hook        (plugin scope, §C.7)
 TB5: build pipeline ──▶ published artifact      (§H — SLSA/Sigstore)
 TB6: landing page ──▶ user download             (§E — checksums + provenance)
```

Six boundaries, crisply enumerable — the property that makes STRIDE-per-element the
right spine for a single-binary CLI (Judge §A.2.1).

---

## §2 — The TB1 capability statement (VERBATIM from architecture §C.1 — binding for LMO D-12)

> **TB1 is the novel one and the AI-agent-specific insight:** in an agent workflow,
> the bash command itself may be adversarial — a prompt-injected agent can craft
> install commands designed to slip past the parser (`npm install $(…)`, exotic
> quoting, alias indirection). **Posture, stated honestly: a PreToolUse gate cannot
> win against an arbitrarily obfuscating shell.** **PenRUSH** is (a) a **hard control
> for cooperative-but-careless flows** — the overwhelmingly common case, (b) a
> **cost-raiser for adversarial ones**, with the **unparseable-install-fails-closed**
> principle (§A.5) closing the cheap evasions. This framing goes verbatim into the
> threat-model doc so marketing can never overclaim (LMO liability-disclosure
> tie-in, D-12).

**Three claims, and only these three, may be made about TB1 in any public surface:**

1. **Cooperative-but-careless = hard control.** For the common case — a developer or
   agent that issues a *normal* install command and simply did not notice the package
   is 3 days old — **PenRUSH** is a reliable, deterministic block. This is the
   product's load-bearing value and it is genuinely strong.
2. **Adversarial = cost-raiser, not a wall.** Against an actively obfuscating shell
   (command substitution, alias indirection, dynamic construction, arbitrary quoting)
   no PreToolUse string-gate can be a guarantee. **PenRUSH** raises the cost and
   removes the cheap evasions; it does not claim to defeat a determined attacker who
   controls the command string.
3. **Unparseable-install-fails-closed.** When a command matches an install verb but
   spec extraction fails (quoting tricks, substitution), the gate **blocks** with an
   "unparseable install command" message rather than silently passing (architecture
   §A.5). The cheap evasions are closed by *failing closed*, not by claiming to parse
   the unparseable.

**Marketing constraint (Judge §C.5 item 2 + CMSD D-15, LMO-reviewed):** a day-2
parser-evasion proof-of-concept is an **expected event, not a refutation** — the
honest-posture framing must ship *in launch messaging* so the first bypass PoC
confirms the stated posture instead of refuting an overclaim. LMO D-12 reviews this
verbatim text before any public claim.

---

## §3 — STRIDE-per-element (architecture §C.2 — the 7 mandated attacks)

| # | Attack (EXECUTION-PLAN §6.1 row C) | STRIDE | Control (this architecture) | Pentest case |
|---|---|---|---|---|
| 1 | Registry MITM | Spoofing / Tampering | TLS-only via Go stdlib system roots; cert validation never disableable (no `--insecure` flag exists, by design); HTTPS-only endpoints; cross-host redirects to non-HTTPS rejected; responses schema-validated + size-capped + strict-decoded before use | **P-1** |
| 2 | Override-flow abuse | Elevation of Privilege | Mandatory reason; 30-day hard expiry (never null); exact-key only (no wildcards); **version-pinned overrides** (a different version re-enters the age gate — PR-P2-02); every use audit-chained; override-rate KPI; v1 team approval | **P-2** |
| 3 | Audit-log tampering | Tampering / Repudiation | SHA-256 chain binding the **literal on-disk bytes** + `penrush audit verify` (exits `ExitTamper(3)`); any edit, key injection, duplicate key, `\uXXXX` re-encode, reorder, deletion, or truncation breaks verification; honest full-re-forge limitation documented (§5); v1 Ed25519 | **P-3** |
| 4 | Signed-binary forgery | Spoofing | Sigstore keyless: Fulcio short-lived certs bound to the GitHub Actions OIDC identity; Rekor transparency log; cosign blob signing; SLSA L3 provenance; reproducible double-build | **P-4** |
| 5 | Plugin sandbox escape | Elevation of Privilege | Minimal plugin scope (§C.7): hooks + bin only — no MCP servers, no agents, no `settings.json` overrides; binary runs at user privilege, requests nothing more (NFR-006 no-root); zero side effects on the block path (NFR-007) | **P-5** |
| 6 | Insider / single-maintainer compromise | Spoofing / Tampering / Repudiation | Branch protection + required review; signed commits; org-wide 2FA; **PSS** GODclaude-only-push rule; SLSA provenance binds artifact→repo→workflow so a hijacked laptop cannot mint an "official" release outside CI | **P-6** |
| 7 | Timing side-channel + gate-check DoS | Information Disclosure / DoS | Timing: cache-state inference is low-value (accepted risk v0, documented §5); DoS: local request coalescing, per-ecosystem registry rate-limit compliance (token buckets), block-until-cooldown-clear caching removes re-poll storms; a DoS'd registry degrades to **fail-closed** (availability sacrificed before integrity, NFR-002) | **P-7** |

**Hardening derived from the internal pentest (this run), folded into the controls above:**

- **Config floor (PR-P2-01):** `cooldown_days` is clamped up to `MinCooldownDays`; a
  below-floor value emits a `policy_changed` audit event. `cooldown_days: 0` can no
  longer globally disable the gate — closes a Tampering/EoP path on row 2/7.
- **Segment-split parsing (PR-TB1-001/002):** the parser splits a command into shell
  segments and classifies each independently; the overall decision is the
  most-restrictive segment. A benign pinned install can no longer launder a chained
  malicious second install (`npm ci && npm install evil@0.0.1`), and the safe-frozen
  short-circuit no longer poisons the whole command — closes two TB1 bypasses on row 1/2.
- **Unicode normalization (PR-TB1-003):** zero-width handling, line/whitespace folding
  (stdlib-only) so a verb hidden by Unicode is recovered, not silently ignored.

---

## §4 — Attack trees (P-9 — Judge §A.3 Supplement 1, Schneier 1999)

STRIDE enumerates threat *categories per element*; it is structurally weak at
*multi-step chains*. The two highest-skill mandated attacks are chains, so each gets a
tree. **Stage-1 (this internal harness) validates the per-link controls; Stage-2
(external firm) attempts to extend the trees** (anchoring-bias control — the firm is
not handed a finished map to confirm).

### §4.1 — Attack tree A: registry MITM chain (row 1)

```
ROOT: agent installs a malicious artifact that PenRUSH approved, via the registry path
│
├── A1. Intercept the registry response in transit
│   ├── A1.1 downgrade TLS to cleartext .......... BLOCKED: HTTPS-only endpoints; no http:// accepted
│   │                                              (verifier: TestGetJSONRejectsNonHTTPS)
│   ├── A1.2 present a forged server certificate .. BLOCKED: stdlib TLS, system-root validation,
│   │                                              never disableable (no --insecure flag exists)
│   ├── A1.3 redirect to an attacker host ......... BLOCKED: CheckRedirect rejects non-HTTPS /
│   │                                              cross-host downgrade redirects
│   └── A1.4 install a malicious root CA on host .. OUT OF MODEL (same-privilege host compromise;
│                                                   documented §C.1 / §5 residual)
│
├── A2. Forge response CONTENT so a new package reads as "old enough to pass"
│   ├── A2.1 inject far-past PublishedAt .......... CONTROL: response strict-decoded + schema-validated;
│   │                                              age comes only from the per-ecosystem authoritative
│   │                                              field; far-past is itself implausible but the gate's
│   │                                              job is age, not plausibility — paired with A2.2
│   ├── A2.2 emit garbage to crash the decoder .... BLOCKED: FuzzRegistryDecode invariant — no panic,
│   │                                              never (nil,nil), Resolution ALWAYS carries a non-zero
│   │                                              PublishedAt (a MITM cannot mint "old→pass" from garbage);
│   │                                              0 crashers in bounded fuzzing
│   └── A2.3 oversized body to exhaust memory ..... BLOCKED: size-capped reads before decode
│
└── A3. Make the gate fail OPEN instead of closed under registry stress
    ├── A3.1 timeout / 5xx / TLS error ............ BLOCKED: fail-closed; override path printed; not cached
    │                                              (verifier: TestRetryingStatusesFailClosed)
    ├── A3.2 429/403 rate-limit flood ............. BLOCKED: honor Retry-After to budget, then fail-closed
    └── A3.3 crash the gate internally ............ BLOCKED: on_internal_error:"block" + panic-recovery
                                                    converts any internal failure to an explicit block
                                                    (P-8; verifier: TestHookPanicRecoversToBlock)
```

**Tree-A readout:** every reachable leaf is BLOCKED except A1.4 (host-level CA
compromise), which is explicitly out of model. There is no chain through Tree A that
turns "new malicious package" into "approved" while the host root store is honest.

### §4.2 — Attack tree B: signed-binary forgery chain (row 4, CI/OIDC/Sigstore)

```
ROOT: a user verifies and trusts a malicious "PenRUSH" binary as genuine
│
├── B1. Get a malicious binary into the official distribution channel
│   ├── B1.1 push malicious code to main ......... BLOCKED: branch protection + required review +
│   │                                              signed commits + GODclaude-only-push (PSS rule)
│   ├── B1.2 build outside CI on a hijacked laptop  BLOCKED: SLSA L3 provenance binds artifact→repo→
│   │        and publish it as "official" .........  workflow; an off-CI build cannot produce matching
│   │                                              provenance bound to the release workflow OIDC identity
│   └── B1.3 tamper the artifact post-build ....... DETECTED: SHA-256 checksums + cosign signature +
│                                                   reproducible double-build (byte-identical or release fails)
│
├── B2. Forge the signature / provenance so the malicious binary verifies
│   ├── B2.1 sign with a stolen long-lived key .... NO TARGET: Sigstore keyless — no long-lived release
│   │                                              key exists to steal (§C.5: "no key to custody")
│   ├── B2.2 mint a Fulcio cert for our identity .. BLOCKED: Fulcio binds the cert to the GitHub Actions
│   │                                              OIDC identity of OUR release workflow; an attacker
│   │                                              cannot assert that identity without controlling the org
│   └── B2.3 hide the signing event .............. DETECTED: every signing event lands in the Rekor
│                                                   public transparency log (append-only, third-party)
│
└── B3. Defeat the user's verification step
    ├── B3.1 user skips verification .............. RESIDUAL (UX): mitigated by the three-line recipe
    │                                              shipped next to the download button (§E.3) — but a
    │                                              user who skips verification is unprotected (honest §5)
    ├── B3.2 substitute the verification recipe ... CONTROL: recipe is identity-pinned
    │                                              (--certificate-identity-regexp) + --source-tag, and a
    │                                              Go test asserts site/index.html and docs/RELEASE.md
    │                                              stay byte-aligned (INT-01; TestSiteRecipe*)
    └── B3.3 Windows SmartScreen confusion ........ RESIDUAL (UX, §H.4/L-2): v0 unsigned-Authenticode;
                                                    documented SmartScreen guidance; not a forgery,
                                                    a reputation-prompt cost
```

**Tree-B readout:** the forgery leaves (B1, B2) are all BLOCKED or have no target
under keyless signing. The residual risk is concentrated entirely in **B3 — the user
skipping or being confused out of verification** — which is a UX/education problem, not
a cryptographic one. This is why "the verification story *is* the brand" (§E.3) and why
the recipe is identity-pinned and lock-stepped to the canonical docs.

---

## §5 — LINDDUN-lite privacy pass (P-10 — Judge §A.3 Supplement 2)

The product collects **zero telemetry** (§I) — but the brand promise (*zero-identity,
zero-phone-home*) makes any privacy regression a **brand-grade** failure, and STRIDE's
single "Information Disclosure" row covers only the timing side-channel. LINDDUN-lite is
applied to the two surfaces that actually hold or emit data.

### §5.1 — Local stores `~/.penrush/` (the Judge's concrete finding)

> **The audit log records the full `command` string. Real install commands embed
> credentials** — `pip install --index-url https://user:TOKEN@private-repo/...`,
> `git clone https://user:pat@github.com/...`. A SHA-256-chained, append-only,
> never-expiring local file that durably stores secrets in plaintext is a LINDDUN
> "Data Disclosure" threat that the STRIDE first-pass did not surface.

| LINDDUN category | Surface | Disposition |
|---|---|---|
| **Data Disclosure** | `audit.jsonl` durably stores command / override-reason / override-key, which can embed credentials | **CONTROLLED (FR-011):** credential redaction at the single `Append` write chokepoint over *every* durable free-text field (command, reason, override-key); the override store redacts the persisted reason; deny reasons are redacted before they leave the process. Honest posture: **defense-in-depth, not a guarantee** — a maintained denylist of credential classes (URL userinfo; `ghp_`/`github_pat_`/`hf_`/`sk_live_`/`AIza` machine tokens; `Authorization: Bearer`/`Basic`; JWTs; `--token`/`--password`/`--api-key`/`curl -u`/`mysql -p` flags; `*_TOKEN=` env). Cannot recognize every secret shape. The structural control (redact every durable field at one chokepoint + bind the literal on-disk bytes in the chain) bounds the durable surface; the ruleset is a corpus that grows with reports. |
| **Linking / Identifying** | `~/.penrush/` content is user-local | Stays on-device; nothing transmitted. No cross-session identifier minted. |
| **Non-repudiation (as a privacy concern)** | append-only audit log | Accepted by design — auditability is the feature; the log is local-only and never streamed in v0. |
| **§G.2 inheritance** | v1 audit-streaming seam would mirror the chain to a hosted endpoint | **Binding requirement carried forward:** the exporter must stream the *redacted* canonical chain, never raw commands. Recorded in the architecture so v1 cannot regress this. |

### §5.2 — Registry-query metadata

| LINDDUN category | Surface | Disposition |
|---|---|---|
| **Detecting / Linking** | each gate check makes a TLS request to a registry, revealing *to that registry* which package a user is evaluating, plus the `penrush/<version>` User-Agent | **Accepted, documented:** this is intrinsic to checking a package's age against its authoritative registry — the same exposure any package manager already creates. **PenRUSH** adds no identifier beyond the standard UA and sends queries only to the registry the user is already installing from. No request is made to any **PenRUSH**-operated endpoint (there is none). |
| **Unawareness** | a user may not know checks hit registries | Documented in the distribution/observability sections; there is no hidden third-party beacon (§E.2, §I). |

---

## §6 — Honest residual risks (the limits, stated — not hidden)

These ship verbatim in the capability statement / SECURITY.md so the product never
overclaims. Each is a deliberate, documented v0 posture, not an undiscovered gap.

1. **Arbitrarily-obfuscating shell (TB1).** No PreToolUse string-gate defeats a
   command string an adversary fully controls. Mitigation: hard control for the common
   case + unparseable-fails-closed + the segment-split/Unicode hardening from this run.
   Stated, not claimed away.
2. **Same-privilege local attacker (TB3).** A process at the user's privilege can
   delete and re-forge the *entire* `~/.penrush/` (audit chain included). The chain
   gives tamper-**evidence** against partial edits, not tamper-**proofing** against full
   replacement. Staged mitigations: v1 Ed25519 entry signing; v1+ opt-in remote
   head-hash anchoring.
3. **Host root-CA compromise (TB1/TB2, Tree-A leaf A1.4).** A malicious root CA in the
   system trust store breaks TLS authentication. **PenRUSH** uses system roots by design
   (no pinning); out of model.
4. **User skips verification (Tree-B leaf B3).** The strongest provenance is worthless
   if the downloader never runs the recipe. Mitigation is UX/education (recipe beside the
   button), not cryptographic.
5. **Timing side-channel (P-7).** Cache hit/miss timing could in principle leak whether
   a package was recently checked. Low-value; **not** mitigated in v0; documented as an
   accepted risk. Stage-2 may quantify it.
6. **Credential-redaction completeness (P-10).** Defense-in-depth denylist, not a
   guarantee; a novel secret shape can survive. Treated as a growing corpus.
7. **Windows unsigned-Authenticode (§H.4/L-2).** Every Windows v0 download hits a
   SmartScreen reputation prompt. A documented UX cost, not a forgery path; revisited at
   v1 with adoption data.

---

## §7 — Framework note (Judge §A.2)

STRIDE is the spine: system-element-centric, and **PenRUSH** has crisply enumerable
trust boundaries; every mandated attack maps to a STRIDE category and terminates in a
testable control + a named pentest case (category → control → verification). PASTA,
OCTAVE, and Trike were considered and rejected on altitude, not quality (Judge §A.2.3).
The two supplements (attack trees §4; LINDDUN-lite §5) cover exactly the two places
STRIDE-by-element is structurally weak: multi-step chains and "our own" data stores.

---

## Sources

- `knowledge/cto/architecture/penrush-phase-0.5.md` §C.1 (TB1 framing — quoted verbatim §2), §C.2 (STRIDE table), §C.5–C.7, §E.2/E.3, §H.4, §I — v1.0-RATIFIED, read 2026-06-18
- `knowledge/pma/specs/penrush/pentest/internal-stage1-scope-spec-v1.md` §2.2 (P-9 attack trees, P-10 LINDDUN-lite) — read 2026-06-18
- `knowledge/judge/audits/penrush-methodology-validation.md` §A.2 (STRIDE SOUND), §A.3 (attack-tree + LINDDUN-lite supplements + audit-log credential-redaction FR), §A.4, §C.5 — read 2026-06-18
- [Microsoft Learn — STRIDE / Threat Modeling Tool threats](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [Schneier, "Attack Trees," Dr. Dobb's Journal, Dec 1999](https://www.schneier.com/academic/archives/1999/12/attack_trees.html)
- [linddun.org — LINDDUN privacy threat modeling, KU Leuven DistriNet](https://linddun.org/)
- Live controls evidenced in `docs/security/ph2-evidence-package.md` and `docs/security/ph2-case-map.md`

*Filed by **CTO**, PH-2 D-9. The §2 TB1 capability statement is verbatim from architecture §C.1 and is the binding input to LMO D-12 liability disclosure. No push (GODclaude-only-push hard rule).*
