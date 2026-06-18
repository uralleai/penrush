// Package redact removes credentials from command strings before they are
// durably stored.
//
// Binding requirement: FR-011 (PRD v1.1) via The Judge D-5 SA.3/SA.4
// (knowledge/judge/audits/penrush-methodology-validation.md) — install
// commands embed secrets (`pip install --index-url https://user:TOKEN@host`),
// and a SHA-256-chained, never-expiring audit log that stores them in
// plaintext is a LINDDUN data-disclosure threat. Redaction happens at WRITE
// time inside the audit writer over EVERY durable free-text field (Command,
// Reason, OverrideKey) and inside the override store; no call path may bypass
// it. Pentest case P-10 verifies.
//
// Coverage is best-effort against an open-ended secret space (architecture
// §B.2). The ruleset is a maintained corpus of credential classes that appear
// in install/setup commands (URL userinfo, machine-token prefixes incl.
// hf_/sk_live_/AIza, Authorization Bearer/Basic, JWT, credential-named flags
// incl. curl -u and mysql -p, credential env-vars). It is defense-in-depth, not
// a guarantee; the structural controls (field-coverage at the Append chokepoint
// and byte-bound tamper-evidence) bound the durable surface.
package redact

import "regexp"

// Marker is the replacement text for redacted material.
const Marker = "[REDACTED]"

type rule struct {
	re   *regexp.Regexp
	repl string
}

// Order matters: URL userinfo first so a token inside a URL is normalized to
// the canonical `user:[REDACTED]@` form before prefix rules see it.
//
// Posture (honest, per architecture §B.2): redaction is best-effort against an
// open-ended secret space. The denylist below covers the credential classes
// that legitimately appear in install/setup commands; it is paired with a
// generic flag-value rule and documented as defense-in-depth, not a guarantee.
// The field-coverage fix (audit.Append redacts every durable field) and the
// byte-binding tamper check are the structural controls; this ruleset reduces
// the residual plaintext surface.
var rules = []rule{
	// 1. URL userinfo with password: scheme://user:secret@host.
	//    Consume the userinfo up to the LAST '@' before the host so a password
	//    that itself contains '@' (e.g. https://user:p@ss:word@host) is fully
	//    redacted, not truncated at the first '@' (INT-04 case 3). The host part
	//    after the final '@' must look like a host (no further '@', no space).
	{regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^\s/]*@([^@\s/]+)`), `${1}` + Marker + `@${2}`},
	// 2. URL userinfo single-token (no colon): scheme://TOKEN@host — GitHub PAT-in-URL
	//    form. The userinfo is replaced entirely.
	{regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)([^/\s:@]+)@`), `${1}` + Marker + `@`},
	// 3. Known machine-token prefixes (GitHub classic + fine-grained, npm, PyPI,
	//    GitLab, Slack, AWS access key id, HuggingFace, Stripe live/test, Google API).
	{regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}\b`), Marker},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{16,}\b`), Marker},
	{regexp.MustCompile(`\bnpm_[A-Za-z0-9]{16,}\b`), Marker},
	{regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{16,}\b`), Marker},
	{regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{10,}\b`), Marker},
	{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), Marker},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), Marker},
	// HuggingFace tokens — common in pip/uv installs from HF index URLs (INT-04 case 1).
	{regexp.MustCompile(`\bhf_[A-Za-z0-9]{16,}\b`), Marker},
	// Stripe secret keys (live + test).
	{regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b`), Marker},
	// Google API key.
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{20,}\b`), Marker},
	// 4. HTTP Authorization headers — Bearer AND Basic (INT-04 case 2), plus the
	//    generic `Authorization: <scheme> <token>` form. The value is redacted to
	//    end-of-token.
	{regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}`), `${1}` + Marker},
	{regexp.MustCompile(`(?i)(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]+`), `${1}` + Marker},
	// Generic `Authorization: Token <x>` (Bearer/Basic have dedicated rules
	// above). Stop at a quote/space so a trailing closing quote is preserved.
	{regexp.MustCompile(`(?i)(Authorization:\s*Token\s+)[^\s"']+`), `${1}` + Marker},
	// 5. JWT (three base64url segments). High-confidence shape; redact whole token.
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b`), Marker},
	// 6. Credential-bearing flag values: --token x | --token=x | --password x |
	//    --api-key x | --auth x | --secret x  (one- or two-dash forms). The value
	//    consumes to the end of a quoted string if the flag value is quoted, so a
	//    secret with spaces inside quotes is fully scrubbed (PRIV-02 partial-leak).
	{regexp.MustCompile(`(?i)(--?(?:token|password|passwd|pwd|api[-_]?key|auth|secret)=)(?:"[^"]*"|'[^']*'|\S+)`), `${1}` + Marker},
	{regexp.MustCompile(`(?i)(--?(?:token|password|passwd|pwd|api[-_]?key|auth|secret)\s+)(?:"[^"]*"|'[^']*'|\S+)`), `${1}` + Marker},
	// 7. curl basic-auth: -u user:pass | --user user:pass  (INT-04 / PRIV-02).
	//    Only the colon-bearing user:pass form is a credential; a bare `-u name`
	//    (e.g. twine's `-u __token__` sentinel) is a username, not a secret, so
	//    it is preserved. Redact the whole user:pass token.
	{regexp.MustCompile(`(?i)(-u\s+|--user[=\s]+)[^\s:]+:\S+`), `${1}` + Marker},
	// 8. Attached single-dash password: -pSECRET (mysql/mariadb -p form, PRIV-02).
	//    Require ≥4 chars to avoid eating bare `-p`.
	{regexp.MustCompile(`(?i)(\s-p)[^\s-]{4,}`), `${1}` + Marker},
	// 9. Env-var assignments of credential-named variables on the command line:
	//    NPM_TOKEN=xyz cmd ...
	{regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|APIKEY|API_KEY)[A-Z0-9_]*=)\S+`), `${1}` + Marker},
}

// String returns cmd with all recognized credential material replaced by
// Marker. Non-credential text is preserved byte-for-byte.
func String(cmd string) string {
	out := cmd
	for _, r := range rules {
		out = r.re.ReplaceAllString(out, r.repl)
	}
	return out
}
