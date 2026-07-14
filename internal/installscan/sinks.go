// Package installscan statically detects the "fetch-a-remote-payload then
// execute it" pattern inside package install-lifecycle hooks (FR-106).
//
// It is PURE STATIC TEXT/JSON analysis. It NEVER executes a hook, a payload, a
// build step, or any nested content (architecture delta §V4.9 — the
// no-execution invariant). Every input is untrusted attacker-authored text; the
// package only reads bytes and matches regexps.
//
// Honest static-only limit (PRD §5.7, verbatim, binding): this is static
// analysis only. It is evadable by obfuscation (base64/hex URLs, string
// concatenation, indirection through a downloaded interpreter) and by
// dynamically-constructed commands. It fails closed on unparseable input. It
// raises attacker cost; it is not proof of safety.
//
// Zero third-party deps (stdlib regexp/strings/bytes/encoding/json only).
package installscan

import "regexp"

// A fetch sink is a network-download primitive: a shell downloader or a
// language HTTP client. Case-insensitive where the token is a program/method
// name. RE2 (no backrefs / lookaround) — safe against catastrophic-backtracking
// DoS by construction (a parser-DoS control, delta §V4.7).
var fetchSinks = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bcurl\b`),
	regexp.MustCompile(`(?i)\bwget\b`),
	regexp.MustCompile(`(?i)\bInvoke-WebRequest\b`),
	regexp.MustCompile(`(?i)\bInvoke-RestMethod\b`),
	regexp.MustCompile(`(?i)\biwr\b`),
	regexp.MustCompile(`(?i)\bStart-BitsTransfer\b`),
	regexp.MustCompile(`(?i)\bNet::HTTP\b`),
	regexp.MustCompile(`(?i)\bopen-uri\b`),
	regexp.MustCompile(`(?i)URI\.open\b`),
	regexp.MustCompile(`(?i)\burllib\b`),
	regexp.MustCompile(`(?i)\burlopen\b`),
	regexp.MustCompile(`(?i)\brequests\.(get|post|head|put|request)\b`),
	regexp.MustCompile(`(?i)\bhttp\.client\b`),
	regexp.MustCompile(`(?i)\b(node-fetch|axios)\b`),
	regexp.MustCompile(`(?i)\bhttps?\.(get|request)\s*\(`),
	regexp.MustCompile(`(?i)\bfetch\s*\(`),
	regexp.MustCompile(`(?i)\b(reqwest|ureq|hyper)\b`),
}

// An exec sink is a shell/interpreter/eval primitive that runs code. Reaching
// one with attacker-supplied fetched bytes is the danger.
var execSinks = []*regexp.Regexp{
	regexp.MustCompile(`\|\s*(ba)?sh\b`),       // ... | sh   ... | bash
	regexp.MustCompile(`\b(ba)?sh\s+-c\b`),     // sh -c   bash -c
	regexp.MustCompile(`\|\s*python[0-9.]*\b`), // ... | python
	regexp.MustCompile(`\|\s*(node|ruby|perl)\b`),
	regexp.MustCompile(`\beval\b`),
	regexp.MustCompile(`\bexec\s*\(`), // Python exec(), JS indirect eval via exec-like call
	regexp.MustCompile(`\bos\.system\b`),
	regexp.MustCompile(`\bsubprocess\b`),
	regexp.MustCompile(`\bPopen\b`),
	regexp.MustCompile(`\bchild_process\b`),
	regexp.MustCompile(`\b(execSync|spawnSync|spawn)\b`),
	regexp.MustCompile(`(?i)\bInvoke-Expression\b`),
	regexp.MustCompile(`(?i)\biex\b`),
	regexp.MustCompile(`\bsystem\s*\(`), // Ruby / C system()
	regexp.MustCompile(`\bKernel\.exec\b`),
	regexp.MustCompile("`[^`\n]*`"),        // backtick command substitution
	regexp.MustCompile(`%x\{`),             // Ruby %x{}
	regexp.MustCompile(`\bCommand::new\b`), // Rust std::process::Command
}

// Obfuscation / indirection markers. When an exec sink co-occurs with one of
// these but no explicit fetch sink is visible, the scanner cannot fully resolve
// what is being executed (a decoded/indirected payload, PRD §5.7
// "indirection through a downloaded interpreter") — the fail-closed case.
var obfuscationMarkers = []*regexp.Regexp{
	regexp.MustCompile(`(?i)base64\s+(-d|--decode|-D)\b`),
	regexp.MustCompile(`(?i)\bb64decode\b`),
	regexp.MustCompile(`(?i)\batob\s*\(`),
	regexp.MustCompile(`(?i)\bunhexlify\b`),
	regexp.MustCompile(`(?i)fromCharCode`),
	regexp.MustCompile(`(?i)\.decode\(\s*['"]?base64`),
	regexp.MustCompile(`(?i)\bInvoke-Expression\b`),
	regexp.MustCompile(`\$\([^)\n]*\)`), // shell command substitution $( ... )
}

func anyMatch(set []*regexp.Regexp, s string) bool {
	for _, re := range set {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// hasFetchSink / hasExecSink / hasObfuscation are the public-ish predicates the
// detector composes. Kept as small funcs so the fuzz + unit tests can exercise
// each independently.
func hasFetchSink(s string) bool   { return anyMatch(fetchSinks, s) }
func hasExecSink(s string) bool    { return anyMatch(execSinks, s) }
func hasObfuscation(s string) bool { return anyMatch(obfuscationMarkers, s) }
