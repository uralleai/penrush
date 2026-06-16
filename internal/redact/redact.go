// Package redact removes credentials from command strings before they are
// durably stored.
//
// Binding requirement: FR-011 (PRD v1.1) via The Judge D-5 SA.3/SA.4
// (knowledge/judge/audits/penrush-methodology-validation.md) — install
// commands embed secrets (`pip install --index-url https://user:TOKEN@host`),
// and a SHA-256-chained, never-expiring audit log that stores them in
// plaintext is a LINDDUN data-disclosure threat. Redaction happens at WRITE
// time inside the audit writer; no call path may bypass it.
// Pentest case P-10 verifies.
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
var rules = []rule{
	// 1. URL userinfo with password: scheme://user:secret@host -> scheme://user:[REDACTED]@host
	{regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@\s]+)@`), `${1}` + Marker + `@`},
	// 2. URL userinfo single-token (no colon): scheme://TOKEN@host — GitHub PAT-in-URL
	//    form. The userinfo is replaced entirely: a bare userinfo segment in an
	//    install command is a credential, not an identity worth preserving.
	{regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)([^/\s:@]+)@`), `${1}` + Marker + `@`},
	// 3. Known machine-token prefixes (GitHub classic + fine-grained, npm, PyPI,
	//    GitLab, Slack, AWS access key id).
	{regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}\b`), Marker},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{16,}\b`), Marker},
	{regexp.MustCompile(`\bnpm_[A-Za-z0-9]{16,}\b`), Marker},
	{regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{16,}\b`), Marker},
	{regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{10,}\b`), Marker},
	{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), Marker},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), Marker},
	// 4. Bearer tokens in header-style arguments.
	{regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}`), `${1}` + Marker},
	// 5. Credential-bearing flag values: --token x | --token=x | --password x |
	//    --api-key x | --auth x | --secret x  (one- or two-dash forms).
	{regexp.MustCompile(`(?i)(--?(?:token|password|passwd|pwd|api[-_]?key|auth|secret)[= ])\S+`), `${1}` + Marker},
	// 6. Env-var assignments of credential-named variables on the command line:
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
