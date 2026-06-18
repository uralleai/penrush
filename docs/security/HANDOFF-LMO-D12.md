# Handoff — PH-2 Security Docs → LMO (D-12) + PH-2 PASS preconditions

| Field | Value |
|---|---|
| **From** | **CTO** |
| **To** | **LMO** (D-12 liability disclosure) — cc PMA, GODclaude |
| **Date** | 2026-06-18 |
| **Re** | PenRUSH PH-2 Stage-1 internal-pentest evidence package + finalized threat model |
| **Status** | 🟡 Internal stage DONE; routed for LMO review. PH-2 PASS still BLOCKED (see §3). |

## 1. Documents routed to LMO

| Doc | Path | What LMO needs from it |
|---|---|---|
| **Threat model (D-9)** | `docs/security/threat-model.md` | **§2 is the binding input to D-12.** The TB1 capability statement is **verbatim from architecture §C.1** — "a PreToolUse gate cannot win against an arbitrarily obfuscating shell; PenRUSH is a hard control for cooperative-but-careless flows and a cost-raiser for adversarial ones; unparseable-install-fails-closed." LMO reviews this text so **marketing (CMSD D-15) cannot overclaim**. The three permitted-claims list in §2 and the residual-risk list in §6 are the honest-limitation surface for the liability disclosure. |
| **Evidence package** | `docs/security/ph2-evidence-package.md` | §1 per-case results, §2 remediation log (24 medium+ findings closed this run), §3 the honest "internal stage cannot certify — reserved for external firm" section. §6 enumerates the PH-2 PASS gates. |
| **Case map (chunk-5)** | `docs/security/ph2-case-map.md` | Verifier-level detail backing the evidence package. |
| **Security policy** | `SECURITY.md` | Coordinated-disclosure policy + FR-011 redaction honest posture (defense-in-depth, not a guarantee). The 90-day embargo norm carried `[NEEDS VERIFICATION]` (Judge §B.2) — **LMO please confirm before SECURITY.md ships publicly.** |

## 2. Specific LMO asks (D-12 + D-1)

1. **D-12 liability disclosure:** confirm the threat-model §2 verbatim TB1 framing is the
   text that governs all public claims; confirm no public surface may exceed the three
   permitted claims. This is the overclaim guardrail.
2. **EU CRA:** Judge §C.5 item 3 flagged EU CRA disclosure liability as a *kill-grade*
   risk with no register row — LMO to confirm whether CRA disclosure obligations are a
   barrier (it is in the kill criteria).
3. **SECURITY.md embargo:** confirm/replace the `typical embargo up to 90 days` norm.
4. **D-1 (parallel):** domain + checkbox/AS-IS text outcome still feeds the site go-live.

## 3. Remaining preconditions for PH-2 PASS (precise — Uri's vs done)

The internal Stage-1 is **DONE**. PH-2 PASS is **NOT** CTO's to declare. Both arms of the
HYBRID verdict plus LMO must clear before any public/OSS go-live:

- ✅ **DONE (CTO):** Stage-1 internal harness — P-1…P-10 + TB1 exercised; **24 medium+
  findings remediated + regression-tested this run**; fuzz #1/#2 (0 crashers), property,
  E2E green; `govulncheck` clean; zero third-party runtime deps; threat-model + evidence
  package filed. One **LOW** fails-closed finding (F-1 cargo override key) tracked, fix
  scheduled before Stage-2 kickoff.
- ⛔ **BLOCKED ON URI — financial authorization:** the **external pentest-firm engagement**
  (HYBRID 2nd arm), target **$20K–35K** (range $15K–50K). **RFP is drafted, NOT sent.**
  Independence is the whole point — the internal stage cannot self-certify (evidence
  package §3). No external engagement proceeds without Uri's explicit financial go.
- ⛔ **BLOCKED ON LMO — E-items:** D-12 (this handoff) + D-1 + CRA + embargo confirmation.
- ⛔ **THEN:** external pentest executed + PASS (zero open critical/high) → CTO regression
  → only then GODclaude opens the internet boundary (public repo + marketplace + CF Pages).

**One-line summary for Uri:** internal pentest done and clean (24 medium+ fixed, only a
LOW fails-closed item left); the two things now standing between us and PH-2 PASS are
**your financial authorization for the external firm (~$20K–35K, RFP ready to send)** and
**LMO's E-items** — together with the external engagement actually executing and passing.

*Filed by **CTO** 2026-06-18. No push (GODclaude-only-push hard rule) — GODclaude routes when ready.*
