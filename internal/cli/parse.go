package cli

// Command-string parser (architecture §A.5).
//
// The `check` subcommand receives pre-split args (`eco`, `pkg@ver`). The hook
// adapter (§F) instead receives a RAW shell command string out of the Claude
// Code PreToolUse payload (`tool_input.command`) and must decide:
//
//   - is this an install-like command at a shell command-position? (if not →
//     allow, the gate has no opinion on `ls`/`git status`/etc.)
//   - if it is, extract (ecosystem, name, version) so the SAME gate engine the
//     `check` path uses can age-gate it — this is what makes the plugin path
//     and the CLI path produce identical verdicts (the §K parity corpus).
//   - some rules are STRUCTURAL and decided here without a registry call,
//     exactly as the reference Python hook decides them: lockfile-frozen modes
//     pass; missing exact-pin blocks; `go install ...@latest` blocks;
//     `claude mcp add` is approval-gated; system package managers
//     (winget/choco/brew/apt) require explicit approval.
//   - the bypass-resistance principle (§A.5, §C.3): a command that matches an
//     install VERB but whose spec cannot be extracted (quoting tricks, command
//     substitution) FAILS CLOSED with an "unparseable install" block — never a
//     silent pass. This is the highest-bypass-risk surface and gets the fuzz
//     budget in chunk 5.
//
// Behavior is ported to stay aligned with the reference oracle
// (~/.claude/hooks/supply-chain-gate.py), which the parity corpus pins.
//
// Zero third-party deps: stdlib regexp/strings only (§A.2).

import (
	"regexp"
	"strings"
	"unicode"
)

// ParseAction is the parser's structural classification of a command.
type ParseAction int

const (
	// ActionIgnore: not an install-like command — the gate allows it untouched.
	ActionIgnore ParseAction = iota
	// ActionAllow: an install command that is safe BY STRUCTURE (lockfile-frozen
	// mode) and needs no registry call.
	ActionAllow
	// ActionBlock: blocked BY STRUCTURE (no registry call) — missing exact-pin,
	// go @latest, system package manager, claude mcp add, or an unparseable
	// install command (fail-closed).
	ActionBlock
	// ActionGate: a parsed install spec to run through the age gate engine. The
	// (Eco, Name, Version) fields are populated; the engine decides pass/block.
	ActionGate
)

// ParseResult is one parsed command's classification.
//
// For ActionGate, Eco/Name/Version are the engine inputs (identical shape to
// what parseCheckArgs yields, so the verdict matches the `check` path).
// For ActionAllow/ActionBlock, Reason carries the human-readable explanation
// and OverrideKey (when non-empty) is the artifact key for the override hint.
type ParseResult struct {
	Action      ParseAction
	Eco         string
	Name        string
	Version     string
	Reason      string
	OverrideKey string // eco:name, for the override path on a structural block
}

// _CMD_POS anchors a verb to a shell command-position: start-of-string or after
// a shell separator (`;`, newline, `&&`, `||`, `|`). Without it the verb words
// match inside arbitrary text (a python -c "..." string, an echo, a grep
// pattern) and trigger false-positive blocks. Mirrors the reference hook's
// _CMD_POS (incident 2026-05-26).
const cmdPos = `(?:^|[;\n\r]|&&|\|\||\|)\s*`

var (
	// Lockfile-frozen / safe-by-design modes: ALLOW without a registry call.
	safeFrozenRes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bnpm\s+ci\b`),
		regexp.MustCompile(`(?i)\bpnpm\s+install\s+(?:[^|;&]*\s)?--frozen-lockfile\b`),
		regexp.MustCompile(`(?i)\byarn\s+install\s+(?:[^|;&]*\s)?--frozen-lockfile\b`),
		regexp.MustCompile(`(?i)\buv\s+sync\s+(?:[^|;&]*\s)?--frozen\b`),
		regexp.MustCompile(`(?i)\bpip3?\s+install\s+(?:[^|;&]*\s)?--require-hashes\b`),
		regexp.MustCompile(`(?i)\bcargo\s+(?:build|install|run)\s+(?:[^|;&]*\s)?--locked\b`),
		regexp.MustCompile(`(?i)\bbundle\s+install\s+(?:[^|;&]*\s)?--frozen\b`),
		regexp.MustCompile(`(?i)\bpoetry\s+install\b`),
	}
	poetryNoLockRe = regexp.MustCompile(`(?i)\bpoetry\s+install\b\s+--no-lock\b`)

	npmAddRe = regexp.MustCompile(`(?i)\bnpm\s+(?:i|install|add)\b`)
	// pnpmYarnAddRe matches `pnpm add` / `yarn add` (npm-ecosystem installs that
	// are NOT lockfile-frozen). A frozen `pnpm/yarn install --frozen-lockfile`
	// is handled by safeFrozenRes; a bare add must be gated/pinned just like
	// `npm install <pkg>` (PR-TB1-001 listed `pnpm add evil` as a live bypass).
	pnpmYarnAddRe = regexp.MustCompile(`(?i)\b(?:pnpm|yarn)\s+add\b`)
	pipInstall    = regexp.MustCompile(`(?i)\bpip3?\s+install\b`)
	uvAddRe       = regexp.MustCompile(`(?i)\buv\s+(?:add|pip\s+install)\b`)
	cargoAddRe    = regexp.MustCompile(`(?i)\bcargo\s+(?:install|add)\b`)
	gemInstall    = regexp.MustCompile(`(?i)\bgem\s+install\b`)
	goGetRe       = regexp.MustCompile(`(?i)\bgo\s+(?:install|get)\s+(\S+@\S+)`)
	// goVerbRe matches `go get`/`go install` at a verb position regardless of
	// whether an @version follows — used to detect the version-less unpinned
	// fetch the /lock file rule must block (PR-TB1-004a).
	goVerbRe   = regexp.MustCompile(`(?i)\bgo\s+(?:install|get)\b`)
	dockerPull = regexp.MustCompile(`(?i)\bdocker\s+(?:pull|run|create)\b`)
	gitCloneRe = regexp.MustCompile(`(?i)\bgit\s+clone\s+(\S+)`)
	// ghCloneVerbRe anchors `gh repo clone` so we can scan its positional args
	// (skipping any leading flags) instead of grabbing the first token — a
	// leading flag was a gate bypass (PR-TB1-004b).
	ghCloneVerbRe = regexp.MustCompile(`(?i)\bgh\s+repo\s+clone\b`)
	claudeMCP     = regexp.MustCompile(`(?i)\bclaude\s+mcp\s+(?:add|install)\b`)

	wingetRe = regexp.MustCompile(`(?i)\bwinget\s+install\b`)
	chocoRe  = regexp.MustCompile(`(?i)\bchoco\s+install\b`)
	brewRe   = regexp.MustCompile(`(?i)\bbrew\s+install\b`)
	aptRe    = regexp.MustCompile(`(?i)\bapt(?:-get)?\s+install\b`)

	// Ephemeral fetch-and-execute (npx / npm exec / pnpm dlx / yarn dlx / bun x /
	// bunx) — command-position-anchored.
	execRes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)` + cmdPos + `npx\b`),
		regexp.MustCompile(`(?i)` + cmdPos + `npm\s+(?:exec|x)\b`),
		regexp.MustCompile(`(?i)` + cmdPos + `pnpm\s+dlx\b`),
		regexp.MustCompile(`(?i)` + cmdPos + `yarn\s+dlx\b`),
		regexp.MustCompile(`(?i)` + cmdPos + `bun\s+x\b`),
		regexp.MustCompile(`(?i)` + cmdPos + `bunx\b`),
	}

	// npmExactPin matches the exact-pin flags (--save-exact / -E).
	npmExactPin = regexp.MustCompile(`(?i)--save-exact\b|(?:^|\s)-E\b`)

	// ghRepoFromURL extracts owner/repo from a github clone URL.
	ghRepoFromURL = regexp.MustCompile(`(?i)(?:github\.com[/:])([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/|$)`)

	// shellControl truncates a tail at the first shell control character.
	shellControl = regexp.MustCompile(`[;&|]|>>?|<`)
	// execSeparator splits exec args from the inner command at a ` -- ` token.
	execSeparator = regexp.MustCompile(`\s+--\s+|\s+--$`)
	whitespaceRe  = regexp.MustCompile(`\s+`)
)

// segmentSeparators splits a normalized command string into independent shell
// segments. A safe-frozen verb (or any classification) in ONE segment must not
// vouch for an install verb in ANOTHER (PR-TB1-001). The separators are the
// shell command-list operators: `;`, `&&`, `||`, `|`, and a newline (already
// normalized to '\n' by normalizeCommand). Splitting BEFORE classification is
// the structural fix for the whole-string short-circuit and first-match-only
// bypasses (PR-TB1-001, PR-TB1-002).
var segmentSeparators = regexp.MustCompile(`&&|\|\||[;|\n]`)

// zeroWidth runes carry no width and are stripped before matching so they
// cannot be smuggled inside a verb word (PR-TB1-003): U+200B ZWSP, U+200C
// ZWNJ, U+200D ZWJ, U+FEFF BOM/ZWNBSP. Written as \u escapes to keep the
// source ASCII-clean.
var zeroWidth = map[rune]bool{
	0x200b: true, 0x200c: true, 0x200d: true, 0xfeff: true,
}

// lineSep runes are Unicode line/paragraph separators that must become a
// command separator so a chained install after them is segmented (PR-TB1-003):
// U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR.
var lineSep = map[rune]bool{0x2028: true, 0x2029: true}

// normalizeCommand folds the Unicode-evasion surface (PR-TB1-003) into a plain
// ASCII-separator form the regex grammar can match, WITHOUT a third-party NFKC
// dependency (zero-deps posture, A.2):
//   - Unicode line separators U+2028/U+2029 become a newline (so segment
//     splitting sees the chained command);
//   - every other Unicode whitespace/separator (NBSP U+00A0, vertical tab,
//     the U+2000-200A block, etc.) becomes an ASCII space, so \s in the verb
//     regexes matches a separator the attacker used to break up verb words;
//   - zero-width characters are handled in TWO ways depending on
//     zeroWidthAsSpace, because their position is ambiguous: a zero-width
//     between verb words (`npm<ZWNJ>install`) must become a SEPARATOR to
//     recover the verb, while a zero-width INSIDE a word (`n<ZWSP>pm`) must be
//     REMOVED to recover the verb. The caller (ParseInstallCommands) classifies
//     under BOTH variants and takes the most-restrictive result, so neither
//     evasion direction slips past — a defense that never under-blocks.
//
// Lossy on SEPARATORS only -- package names and flags are otherwise preserved.
// Case/width of name characters is not folded (a registry-resolution concern,
// not a verb-evasion one).
func normalizeCommand(cmd string, zeroWidthAsSpace bool) string {
	var b strings.Builder
	b.Grow(len(cmd))
	for _, r := range cmd {
		switch {
		case zeroWidth[r]:
			if zeroWidthAsSpace {
				b.WriteByte(' ')
			} // else: drop
		case lineSep[r]:
			b.WriteByte('\n')
		case r == '\n' || r == '\r':
			b.WriteRune(r) // keep ASCII line breaks (cmdPos/segment handle them)
		case r == ' ':
			b.WriteByte(' ')
		case unicode.IsSpace(r):
			// All remaining Unicode whitespace (incl. NBSP, vtab, the U+2000
			// block) collapses to an ASCII space so the verb regexes match.
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// hasZeroWidth reports whether cmd contains any zero-width character, so the
// dual-variant classification is only paid for when it matters.
func hasZeroWidth(cmd string) bool {
	for _, r := range cmd {
		if zeroWidth[r] {
			return true
		}
	}
	return false
}

// splitSegments returns the independent shell segments of a normalized command.
// Empty/blank segments are dropped.
func splitSegments(norm string) []string {
	parts := segmentSeparators.Split(norm, -1)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

// ParseInstallCommands classifies EVERY install-bearing shell segment of a raw
// command string and returns one ParseResult per segment that the gate has an
// opinion on (PR-TB1-001, PR-TB1-002). Segments the gate ignores
// (ActionIgnore) are dropped from the slice; if NO segment is install-like, a
// single ActionIgnore is returned so callers can treat the whole command as
// "allow, no opinion".
//
// Each segment is classified INDEPENDENTLY: a lockfile-frozen (ActionAllow)
// segment cannot vouch for an install verb in another segment, and a benign
// pinned install in one segment cannot launder a malicious install in another.
// The hook/check caller takes the MOST-RESTRICTIVE decision across the slice
// (block > gate-then-block > allow).
func ParseInstallCommands(cmd string) []ParseResult {
	// Two normalization variants for zero-width handling (see normalizeCommand):
	// "drop" recovers a verb split INSIDE a word, "as-space" recovers a verb
	// split BETWEEN words. We classify under both and keep the more-restrictive
	// per aligned segment, so neither evasion direction slips. When the command
	// has no zero-width character, the single variant is used (no extra work).
	primary := segmentsOf(normalizeCommand(cmd, false))
	if !hasZeroWidth(cmd) {
		return collect(classifyAll(primary))
	}
	alt := segmentsOf(normalizeCommand(cmd, true))
	results := classifyAll(primary)
	altResults := classifyAll(alt)
	// Merge: a command is malicious if EITHER variant finds a non-ignored verb.
	// We cannot align segments index-for-index across variants (zero-width
	// changes the split), so we union both result sets and let the caller take
	// the most-restrictive overall. For the per-segment slice we return whichever
	// variant produced the more-restrictive overall decision, preserving each
	// surfaced install.
	if rank(mostRestrictive(altResults).Action) > rank(mostRestrictive(results).Action) {
		results = altResults
	}
	return collect(results)
}

// segmentsOf strips the shell wrapper and splits into segments.
func segmentsOf(norm string) []string {
	return splitSegments(stripShellWrapper(norm))
}

// classifyAll classifies every segment, keeping ignored ones (the caller
// filters); used so both variants produce comparable slices.
func classifyAll(segments []string) []ParseResult {
	out := make([]ParseResult, 0, len(segments))
	for _, seg := range segments {
		out = append(out, classifySegment(seg))
	}
	return out
}

// collect drops ActionIgnore results; returns a single ignore if none remain.
func collect(results []ParseResult) []ParseResult {
	var out []ParseResult
	for _, pr := range results {
		if pr.Action != ActionIgnore {
			out = append(out, pr)
		}
	}
	if len(out) == 0 {
		return []ParseResult{{Action: ActionIgnore}}
	}
	return out
}

// rank scores an action by restrictiveness (shared with mostRestrictive).
func rank(a ParseAction) int {
	switch a {
	case ActionBlock:
		return 3
	case ActionGate:
		return 2
	case ActionAllow:
		return 1
	default: // ActionIgnore
		return 0
	}
}

// ParseInstallCommand is the single-result compatibility shim. It returns the
// MOST-RESTRICTIVE segment result so existing single-result callers cannot be
// laundered by a chained second install (PR-TB1-001/002). Precedence:
// ActionBlock > ActionGate > ActionAllow > ActionIgnore. Among multiple gates
// it returns the first (the engine is invoked on each by the hook path that
// uses ParseInstallCommands).
func ParseInstallCommand(cmd string) ParseResult {
	results := ParseInstallCommands(cmd)
	return mostRestrictive(results)
}

// mostRestrictive folds a per-segment slice into one result by severity.
func mostRestrictive(results []ParseResult) ParseResult {
	best := ParseResult{Action: ActionIgnore}
	for _, r := range results {
		if rank(r.Action) > rank(best.Action) {
			best = r
		}
	}
	return best
}

// classifySegment classifies ONE shell segment (no separators inside). It is
// the former body of ParseInstallCommand, operating on a single, already
// Unicode-normalized segment.
func classifySegment(inner string) ParseResult {
	// Safe-frozen modes pass immediately (but `poetry install --no-lock` does
	// NOT — it opts out of the lockfile). Scoped to THIS segment only.
	if isSafeFrozen(inner) {
		return ParseResult{Action: ActionAllow, Reason: "lockfile-frozen mode"}
	}

	// --- npm install <pkg> --- (also npm i / npm add)
	if m := npmAddRe.FindStringIndex(inner); m != nil {
		pkgs := positionalArgs(inner, m[1])
		if len(pkgs) > 0 { // bare `npm install` = restore from lockfile → allow
			// Exact-pin requirement (/lock file): all named adds must pin.
			if !npmExactPin.MatchString(inner) {
				return ParseResult{
					Action: ActionBlock,
					Reason: "npm install must pin exact version: add --save-exact (or -E). " +
						"Suggested: npm install --save-exact " + strings.Join(pkgs, " "),
				}
			}
			name, version := parseNPMSpec(pkgs[0])
			return gateResult("npm", name, version)
		}
	}

	// --- pnpm add / yarn add <pkg> --- (npm-ecosystem, NOT lockfile-frozen)
	// A frozen `pnpm/yarn install --frozen-lockfile` was already allowed above;
	// a bare add is an unpinned install and must be gated through the npm
	// resolver (PR-TB1-001 listed `pnpm add evil` as a live bypass). pnpm/yarn
	// do not have an npm-style --save-exact gate here, so we age-gate the named
	// package directly (a young/unknown package then blocks on age).
	if m := pnpmYarnAddRe.FindStringIndex(inner); m != nil {
		pkgs := positionalArgs(inner, m[1])
		if len(pkgs) > 0 {
			name, version := parseNPMSpec(pkgs[0])
			return gateResult("npm", name, version)
		}
	}

	// --- pip install ---
	if m := pipInstall.FindStringIndex(inner); m != nil {
		tail := strings.TrimSpace(inner[m[1]:])
		if regexp.MustCompile(`(?i)(?:^|\s)(?:-r|--requirement)(?:\s|$)`).MatchString(tail) {
			return ParseResult{
				Action: ActionBlock,
				Reason: "pip install -r requires --require-hashes to enforce lockfile integrity. " +
					"Use pip install -r requirements.txt --require-hashes.",
			}
		}
		pkgs := positionalArgs(inner, m[1])
		if len(pkgs) > 0 {
			spec := pkgs[0]
			name, version := parsePipSpec(spec)
			if !strings.Contains(spec, "==") {
				pin := "<exact>"
				if version != "" {
					pin = version
				}
				return ParseResult{
					Action: ActionBlock,
					Reason: "pip install of '" + name + "' must pin exact version: pip install " + name + "==" + pin + ".",
				}
			}
			return gateResult("pypi", name, version)
		}
	}

	// --- uv add / uv pip install ---
	if m := uvAddRe.FindStringIndex(inner); m != nil {
		pkgs := positionalArgs(inner, m[1])
		if len(pkgs) > 0 {
			name, version := parsePipSpec(pkgs[0])
			return gateResult("pypi", name, version)
		}
	}

	// --- npx / npm exec / pnpm dlx / yarn dlx / bun x / bunx ---
	for _, re := range execRes {
		m := re.FindStringIndex(inner)
		if m == nil {
			continue
		}
		pkgs := execArgs(inner, m[1])
		// No package (bare npx REPL, flags only) OR a local-file invocation:
		// nothing to gate.
		var spec string
		for _, p := range pkgs {
			if isLocalFile(p) {
				continue
			}
			spec = p
			break
		}
		if spec == "" {
			continue // fall through to other matchers / ignore
		}
		name, version := parseNPMSpec(spec)
		return gateResult("npm", name, version)
	}

	// --- docker pull / run / create ---
	if m := dockerPull.FindStringIndex(inner); m != nil {
		toks := positionalArgs(inner, m[1])
		if len(toks) > 0 {
			image := toks[0]
			// The gate engine's docker resolver enforces digest-pinning; we feed
			// it the same (name, version) split the `check` path uses (split on
			// the LAST '@'/':' — see splitVersion). Digest pins pass; tag-only
			// non-Hub blocks; Hub tags age-gate. Keep the structural decision in
			// the engine for exact parity.
			name, version := splitDockerRef(image)
			return gateResult("docker", name, version)
		}
	}

	// --- git clone (host-anchored: only a github.com URL is in scope) ---
	if m := gitCloneRe.FindStringSubmatch(inner); m != nil {
		if gh := ghRepoFromURL.FindStringSubmatch(m[1]); gh != nil {
			owner, repo := gh[1], strings.TrimSuffix(gh[2], ".git")
			return gateResult("github", owner+"/"+repo, "")
		}
		// Non-GitHub git clone: out of scope (no publish-age source).
	}

	// --- gh repo clone --- (DELIBERATE improvement over the reference oracle,
	// documented per arch §K: the `gh` CLI defaults to github.com, so it accepts
	// a bare `owner/repo` shorthand with no host. The reference Python hook only
	// matched a full github.com URL and silently ignored the shorthand — a
	// gate-bypass gap. We gate both forms here, block-biased per the hard rule.)
	if m := ghCloneVerbRe.FindStringIndex(inner); m != nil {
		// Scan ALL tokens after the verb (flag-skipping), not just the first one.
		// A leading flag (`gh repo clone -- owner/repo`,
		// `gh repo clone --upstream-remote-name x owner/repo`) previously made the
		// captured token a flag, which bareOwnerRepo rejected → silent ignore
		// (PR-TB1-004b). We instead find the first token that is a github URL or
		// a bare owner/repo. A flag VALUE like `x` (after
		// --upstream-remote-name) has no '/' and matches neither, so it is
		// correctly skipped. The `--` git-passthrough separator is a flag token.
		tail := strings.TrimSpace(inner[m[1]:])
		if loc := shellControl.FindStringIndex(tail); loc != nil {
			tail = tail[:loc[0]]
		}
		for _, tok := range whitespaceRe.Split(tail, -1) {
			if tok == "" || tok == "--" || strings.HasPrefix(tok, "-") {
				continue
			}
			arg := strings.TrimSuffix(tok, ".git")
			if gh := ghRepoFromURL.FindStringSubmatch(arg); gh != nil {
				return gateResult("github", gh[1]+"/"+strings.TrimSuffix(gh[2], ".git"), "")
			}
			if owner, repo, ok := bareOwnerRepo(arg); ok {
				return gateResult("github", owner+"/"+repo, "")
			}
			// A bare token that is neither a URL nor owner/repo (a flag value, a
			// local dir name): keep scanning — the real repo arg may follow.
		}
	}

	// --- claude mcp add --- (always approval-gated; the engine's MCP resolver
	// returns ErrApprovalRequired so this routes through the gate for an
	// identical, override-able verdict).
	if claudeMCP.MatchString(inner) {
		toks := positionalArgs(inner, claudeMCP.FindStringIndex(inner)[1])
		server := ""
		if len(toks) > 0 {
			server = toks[0]
		}
		if server == "" {
			// Unparseable mcp add (no server name): fail closed.
			return ParseResult{
				Action:      ActionBlock,
				Reason:      "claude mcp add detected but the server name could not be parsed — fail-closed. Adding an MCP server requires explicit approval.",
				OverrideKey: "",
			}
		}
		return gateResult("mcp", server, "")
	}

	// --- system / distro package managers: always require explicit approval ---
	switch {
	case wingetRe.MatchString(inner) || chocoRe.MatchString(inner):
		return ParseResult{
			Action: ActionBlock,
			Reason: "system package install (winget/choco) detected — these bypass cool-down detection and require explicit approval before running.",
		}
	case brewRe.MatchString(inner) || aptRe.MatchString(inner):
		return ParseResult{
			Action: ActionBlock,
			Reason: "distro package install (brew/apt) detected — these bypass cool-down detection and require explicit approval before running.",
		}
	}

	// --- cargo add / cargo install ---
	if m := cargoAddRe.FindStringIndex(inner); m != nil {
		pkgs := positionalArgs(inner, m[1])
		if len(pkgs) > 0 {
			name := splitOnFirst(pkgs[0], "@=")
			return gateResult("cargo", name, "")
		}
	}

	// --- gem install ---
	if m := gemInstall.FindStringIndex(inner); m != nil {
		pkgs := positionalArgs(inner, m[1])
		if len(pkgs) > 0 {
			name := splitOnFirst(pkgs[0], ":")
			return gateResult("gem", name, "")
		}
	}

	// --- go get / go install <mod>@<ver> ---
	if m := goGetRe.FindStringSubmatch(inner); m != nil {
		spec := m[1]
		if strings.HasSuffix(spec, "@latest") {
			base := spec
			if i := strings.LastIndex(spec, "@"); i >= 0 {
				base = spec[:i]
			}
			return ParseResult{
				Action: ActionBlock,
				Reason: "`go install ...@latest` is forbidden — pin to a specific version: " + base + "@v1.x.y",
			}
		}
		// Pinned: split module@version and age-gate via the Go proxy resolver.
		if i := strings.LastIndex(spec, "@"); i > 0 {
			return gateResult("go", spec[:i], spec[i+1:])
		}
	}

	// --- version-less `go get`/`go install <module>` --- (PR-TB1-004a)
	// An @version-less go fetch is an UNPINNED fetch — the same /lock file
	// violation `npm install foo` (no version) and `pip install foo` (no ==)
	// hit. The goGetRe above only matches `\S+@\S+`, so a version-less form
	// previously fell through to ActionIgnore (silent ALLOW). Block it as
	// missing-pin for symmetry. (Flags like `go get -u`, `go get ./...`, and a
	// bare `go get`/`go mod`-style maintenance call carry no installable module
	// positional and are NOT blocked.)
	if m := goVerbRe.FindStringIndex(inner); m != nil {
		mods := positionalArgs(inner, m[1])
		var mod string
		for _, p := range mods {
			// Skip local/relative module patterns (`./...`, `.`, `all`) — these
			// build the current module, they do not fetch a new one.
			if isLocalFile(p) || p == "." || p == "all" || p == "./..." {
				continue
			}
			mod = p
			break
		}
		if mod != "" {
			base := mod
			if i := strings.LastIndex(mod, "@"); i > 0 {
				base = mod[:i] // defensive: @version already handled above
			}
			return ParseResult{
				Action: ActionBlock,
				Reason: "`go " + goVerb(inner) + " " + base + "` is an unpinned fetch — pin an exact version: " + base + "@v1.x.y (the /lock file rule applies to go modules too).",
			}
		}
	}

	return ParseResult{Action: ActionIgnore}
}

// goVerb returns "get" or "install" for the matched go fetch verb (for the
// blocked-reason message). Defaults to "get".
func goVerb(inner string) string {
	if regexp.MustCompile(`(?i)\bgo\s+install\b`).MatchString(inner) {
		return "install"
	}
	return "get"
}

// gateResult builds an ActionGate result, or an ActionBlock fail-closed result
// if the install verb matched but the artifact name came out empty (the
// unparseable-install principle, §A.5/§C.3).
func gateResult(eco, name, version string) ParseResult {
	if strings.TrimSpace(name) == "" {
		return ParseResult{
			Action: ActionBlock,
			Reason: "unparseable " + eco + " install command — the artifact name could not be extracted (quoting/substitution?). Fail-closed: re-issue the command with a literal package name, or add an override after manual review.",
		}
	}
	return ParseResult{Action: ActionGate, Eco: eco, Name: name, Version: version}
}

// stripShellWrapper removes a leading `bash -c '` / `sh -c "` etc. wrapper so
// the inner command is analyzed. Mirrors the reference hook.
func stripShellWrapper(cmd string) string {
	re := regexp.MustCompile(`^(?:bash|sh|cmd|powershell)\s+-[ec]\s+['"]`)
	return re.ReplaceAllString(strings.TrimSpace(cmd), "")
}

func isSafeFrozen(cmd string) bool {
	if poetryNoLockRe.MatchString(cmd) {
		// poetry install --no-lock is NOT frozen; let other matchers (none) run.
		// Strip the poetry-install safe pattern for this command by checking the
		// others only.
		for _, re := range safeFrozenRes[:len(safeFrozenRes)-1] { // exclude poetry
			if re.MatchString(cmd) {
				return true
			}
		}
		return false
	}
	for _, re := range safeFrozenRes {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// positionalArgs returns non-flag tokens after a match position, truncated at
// the first shell control character. Mirrors the reference hook's args_after.
func positionalArgs(cmd string, matchEnd int) []string {
	tail := strings.TrimSpace(cmd[matchEnd:])
	if loc := shellControl.FindStringIndex(tail); loc != nil {
		tail = tail[:loc[0]]
	}
	var out []string
	for _, t := range whitespaceRe.Split(strings.TrimSpace(tail), -1) {
		if t == "" || strings.HasPrefix(t, "-") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// execArgs extracts the npm package(s) fetched-and-executed by an ephemeral
// exec verb. Mirrors the reference hook's parse_exec_args: honors -p/--package
// (space and = forms), skips -c <shellcmd>, stops at the ` -- ` separator, and
// falls back to the first bare positional.
func execArgs(cmd string, matchEnd int) []string {
	tail := strings.TrimSpace(cmd[matchEnd:])
	if loc := shellControl.FindStringIndex(tail); loc != nil {
		tail = tail[:loc[0]]
	}
	if loc := execSeparator.FindStringIndex(tail); loc != nil {
		tail = tail[:loc[0]]
	}
	toks := whitespaceRe.Split(strings.TrimSpace(tail), -1)

	var explicit []string
	var bare string
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t == "" {
			continue
		}
		switch {
		case t == "-p" || t == "--package":
			if i+1 < len(toks) {
				explicit = append(explicit, toks[i+1])
				i++
			}
		case strings.HasPrefix(t, "--package=") || strings.HasPrefix(t, "-p="):
			if _, val, found := strings.Cut(t, "="); found && val != "" {
				explicit = append(explicit, val)
			}
		case t == "-c":
			i++ // skip the shell-cmd token
		case strings.HasPrefix(t, "-"):
			// other flag: skip
		default:
			if bare == "" {
				bare = t
			}
		}
	}
	if len(explicit) > 0 {
		return explicit
	}
	if bare != "" {
		return []string{bare}
	}
	return nil
}

// parseNPMSpec splits an npm spec: left-pad@1.2.3 -> (left-pad, 1.2.3);
// @scope/pkg@1.0.0 -> (@scope/pkg, 1.0.0). Matches splitVersion semantics
// (split on the LAST '@', a leading '@' is a scope).
func parseNPMSpec(spec string) (name, version string) {
	if i := strings.LastIndex(spec, "@"); i > 0 {
		return spec[:i], spec[i+1:]
	}
	return spec, ""
}

// parsePipSpec splits a pip spec: foo==1.2.3 -> (foo, 1.2.3);
// foo[extra]==1.0 -> (foo, 1.0). Mirrors the reference hook.
func parsePipSpec(spec string) (name, version string) {
	name = splitOnFirst(spec, "=<>~![")
	if m := regexp.MustCompile(`==\s*([^\s,;]+)`).FindStringSubmatch(spec); m != nil {
		version = m[1]
	}
	return name, version
}

// splitDockerRef splits an image reference the same way the `check` path does
// (splitVersion: split on the LAST '@' or ':' so image@sha256:... puts the
// digest in the version slot, and image:tag puts the tag there).
func splitDockerRef(ref string) (name, version string) {
	if i := strings.LastIndex(ref, "@"); i > 0 {
		return ref[:i], ref[i+1:]
	}
	// Tag split on the last ':' AFTER the final '/' (host:port is not a tag).
	lastSlash := strings.LastIndex(ref, "/")
	if c := strings.LastIndex(ref, ":"); c > lastSlash && c > 0 {
		return ref[:c], ref[c+1:]
	}
	return ref, ""
}

// splitOnFirst returns the substring before the first byte in `chars`.
func splitOnFirst(s, chars string) string {
	if i := strings.IndexAny(s, chars); i >= 0 {
		return s[:i]
	}
	return s
}

// bareOwnerRepo accepts a `gh repo clone` shorthand of the form `owner/repo`
// (the gh CLI's github.com default). It rejects flags, URLs, and anything with
// more than one path segment so it cannot be tricked into gating a non-repo
// token.
func bareOwnerRepo(arg string) (owner, repo string, ok bool) {
	if arg == "" || strings.HasPrefix(arg, "-") || strings.Contains(arg, "://") || strings.Contains(arg, ":") {
		return "", "", false
	}
	owner, repo, ok = strings.Cut(arg, "/")
	if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", "", false
	}
	return owner, repo, true
}

func isLocalFile(spec string) bool {
	return strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") ||
		strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, `.\`) ||
		strings.HasPrefix(spec, `..\`)
}
