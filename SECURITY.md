# Security Policy — **PenRUSH**

**PenRUSH** is a supply-chain safety tool. Holding it to a lower security bar than
it asks of the artifacts it gates would be incoherent, so this policy is part of
the product, not an afterthought. (This file closes the coordinated-disclosure
gap the Judge flagged on the release pipeline.)

## Supported versions

Until the first stable release, **only the latest tagged release** receives
security fixes. Pre-`v1.0.0` tags are not separately patched — upgrade to the
newest tag. Once `v1.x` ships, this table will enumerate the supported line(s).

| Version | Supported |
|---|---|
| latest tagged release | yes |
| older tags | no — upgrade |

## Reporting a vulnerability (coordinated disclosure)

**Please do not open a public issue for a security vulnerability.** Public issues
disclose the problem to attackers before a fix exists.

Instead, use **GitHub Private Vulnerability Reporting** for this repository:

> Repository **Security** tab → **Report a vulnerability** → fill in the advisory
> draft.

This is the security-advisory channel for **PenRUSH**. It opens a private
GitHub Security Advisory visible only to the maintainers and you, with no
long-lived secret (e.g. a security mailbox or PGP key) to custody — consistent
with the project's "no key to protect" posture (architecture §C.5). If private
reporting is ever unavailable, request a private channel by opening a *minimal,
non-technical* issue titled "security contact request" (no vulnerability detail)
and a maintainer will respond with a private route.

Please include, as far as you can determine it:

- the affected component (CLI subcommand, an ecosystem resolver, the gate engine,
  the Claude Code plugin shim, or the release pipeline);
- the **PenRUSH** version (`penrush version`) and OS/arch;
- a description of the issue and its security impact (e.g. a gate bypass, a
  fail-**open** path, audit-log tampering that survives `penrush audit verify`, a
  signature/provenance forgery, or a path that strands the user);
- reproduction steps or a proof-of-concept, if available.

A gate that can be made to **fail open**, an audit entry that can be mutated
without breaking the hash chain, or any path that forges or bypasses the SLSA
provenance / cosign signature is considered **high severity**.

## Our commitment (response targets)

These are good-faith targets for a small maintainer team; pre-`v1.0.0` they are
best-effort, not contractual.

| Stage | Target |
|---|---|
| Acknowledge your report | within 3 business days |
| Initial severity assessment | within 7 business days |
| Fix or documented mitigation for high-severity issues | as fast as practical; coordinated with you |
| Public disclosure | after a fix ships, by mutual agreement (typical embargo up to 90 days) |

We will credit reporters who wish to be named once the advisory is published.

## Safe-harbor

Good-faith security research conducted under this policy — testing your own
installation, not accessing other users' data, not degrading others' service,
and giving us reasonable time to remediate before public disclosure — is welcome.
We will not pursue or support action against researchers who follow it.

## Scope

In scope: the **PenRUSH** CLI, its ecosystem resolvers, the gate engine, the
audit log, the override store, the Claude Code plugin shim, and the release /
signing pipeline in this repository.

Out of scope: third-party registries **PenRUSH** queries (npm, PyPI, crates.io,
RubyGems, the Go module proxy, Docker registries) — report those to the
respective registry; and the security of artifacts **PenRUSH** evaluates (that is
the whole point of the gate, not a bug in it).

## Data handling & audit-log redaction (FR-011)

**PenRUSH** stores its decisions in a local, SHA-256-chained `~/.penrush/audit.jsonl`
and never phones home. Install/override commands can embed credentials (a token
in an index-URL, a `--reason` that pastes a secret), so every durably stored
free-text field — the command, the verdict/override reason, and the override key —
is run through a credential redactor at the single audit write chokepoint, and the
override store redacts the reason it persists. Deny reasons returned to the agent
are redacted before they leave the process.

**Honest posture:** redaction is **defense-in-depth, not a guarantee.** It is a
maintained denylist of credential classes that appear in install/setup commands
(URL userinfo, machine-token prefixes such as `ghp_`/`hf_`/`sk_live_`/`AIza`,
HTTP `Authorization: Bearer`/`Basic`, JWTs, credential-named flags including
`curl -u` and `mysql -p`, and credential env-vars). It cannot recognize every
possible secret shape. The structural controls — redacting **every** durable
field at one chokepoint, and binding the **literal on-disk bytes** in the
tamper-evidence chain (`penrush audit verify`) — bound the durable surface;
the regex ruleset reduces the residual plaintext within it. If you find a
credential class that survives into `audit.jsonl`, please report it (see above);
we treat the ruleset as a corpus that grows with reports.

The chain provides tamper-**evidence** against partial edits (any edit, key
injection, duplicate key, re-escaping, reorder, deletion, or truncation breaks
`penrush audit verify`, which exits non-zero so CI/cron can detect it), **not**
tamper-**proofing** against a local attacker who can delete and re-forge the
entire file at the user's privilege.

## External security audit (PH-2)

Before any public / open-source release, **PenRUSH** must pass an independent
penetration test (**PH-2**, non-skippable and non-compressible). The internal
Stage-1 preparation covers the seven STRIDE attack cases (registry MITM,
override-flow abuse, audit-log tampering, signed-binary forgery, plugin sandbox
escape, single-maintainer compromise, and timing-side-channel / gate-check DoS),
plus fuzz and property tests. The result will be summarized here when complete.

## Verifying a release

Every release ships SHA-256 checksums, a Sigstore (cosign) signature, and SLSA
Level 3 provenance. The full verification recipe — confirming an artifact was
built by this repository's release workflow and not tampered with — is in
[`docs/RELEASE.md`](docs/RELEASE.md). Verifying is encouraged for every download.
