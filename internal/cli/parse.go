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

	npmAddRe   = regexp.MustCompile(`(?i)\bnpm\s+(?:i|install|add)\b`)
	pipInstall = regexp.MustCompile(`(?i)\bpip3?\s+install\b`)
	uvAddRe    = regexp.MustCompile(`(?i)\buv\s+(?:add|pip\s+install)\b`)
	cargoAddRe = regexp.MustCompile(`(?i)\bcargo\s+(?:install|add)\b`)
	gemInstall = regexp.MustCompile(`(?i)\bgem\s+install\b`)
	goGetRe    = regexp.MustCompile(`(?i)\bgo\s+(?:install|get)\s+(\S+@\S+)`)
	dockerPull = regexp.MustCompile(`(?i)\bdocker\s+(?:pull|run|create)\b`)
	gitCloneRe = regexp.MustCompile(`(?i)\bgit\s+clone\s+(\S+)`)
	ghCloneRe  = regexp.MustCompile(`(?i)\bgh\s+repo\s+clone\s+(\S+)`)
	claudeMCP  = regexp.MustCompile(`(?i)\bclaude\s+mcp\s+(?:add|install)\b`)

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

// ParseInstallCommand classifies a raw shell command string.
//
// It returns one ParseResult: ActionIgnore for non-install commands,
// ActionAllow/ActionBlock for structurally-decided ones, or ActionGate with a
// populated (Eco, Name, Version) to hand to gate.Engine.CheckGate1.
//
// Multi-package install commands: this returns the FIRST artifact that needs
// gating (the hook adapter calls the engine on it). A structural block (missing
// pin / system pkg / @latest) short-circuits ahead of any age gating, matching
// the reference hook's evaluation order.
func ParseInstallCommand(cmd string) ParseResult {
	inner := stripShellWrapper(cmd)

	// Safe-frozen modes pass immediately (but `poetry install --no-lock` does
	// NOT — it opts out of the lockfile).
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
	if m := ghCloneRe.FindStringSubmatch(inner); m != nil {
		arg := strings.TrimSuffix(m[1], ".git")
		if gh := ghRepoFromURL.FindStringSubmatch(arg); gh != nil {
			return gateResult("github", gh[1]+"/"+strings.TrimSuffix(gh[2], ".git"), "")
		}
		if owner, repo, ok := bareOwnerRepo(arg); ok {
			return gateResult("github", owner+"/"+repo, "")
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

	return ParseResult{Action: ActionIgnore}
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
