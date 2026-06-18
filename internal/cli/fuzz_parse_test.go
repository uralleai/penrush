package cli

// Fuzz target #1 — the command/install parser (architecture §K Fuzz row;
// scope spec §2.1 fuzz #1). This is the chunk-5 pentest TB1 surface: the
// command string is UNTRUSTED (§C.1) and, in an agent workflow, may be
// adversarial — a prompt-injected agent can craft install commands designed to
// slip past the parser. ParseInstallCommand is the highest-bypass-risk and
// highest-false-positive-risk component (§A.5, §C.3), so it gets the fuzz
// budget.
//
// What the fuzzer attacks (TB1 + threat-model §C.1 honest posture):
//   - obfuscated/quoted/substituted install commands that should fail closed,
//     never silently parse to a benign-looking ActionIgnore;
//   - inputs that crash the parser. A panic in the parser is not a mere bug:
//     per §C.6 a crashing gate is a BYPASS PRIMITIVE (the PreToolUse hook would
//     exit non-2 and the tool call would proceed). The harness must prove the
//     parser cannot be crashed by any byte sequence.
//
// INVARIANTS asserted for every input (the security contract, not just "no
// panic"):
//
//  1. No panic / no infinite loop (bounded by go test's per-input timeout).
//  2. The returned Action is always one of the four defined constants — the
//     parser never returns an out-of-range action that a switch would treat as
//     a default-allow.
//  3. FAIL-CLOSED on ambiguity: if the result is ActionGate, the extracted
//     Name MUST be non-empty after trimming. An ActionGate with a blank name
//     would hand the engine an empty artifact key — the unparseable-pass
//     bypass §A.5 exists to prevent. (gateResult enforces this; the fuzzer
//     proves no path around gateResult re-introduces it.)
//  4. ActionGate always carries a known ecosystem key (the same set the engine
//     dispatches on). An unknown eco would make the engine fail closed, but a
//     gate result naming a bogus eco is itself a parser bug — pin it here.
//  5. Determinism: the same input parsed twice yields the same Action — the
//     parser holds no mutable state and must not (a stateful parser is a
//     time-of-check/time-of-use bypass surface).
//
// Run bounded:  go test ./internal/cli/ -run x -fuzz FuzzParseInstallCommand -fuzztime=30s
// Seed corpus is checked in under internal/cli/testdata/fuzz/FuzzParseInstallCommand/.

import "testing"

// gateableEcosystems is the set an ActionGate result may legitimately name —
// identical to the engine's resolver dispatch keys (cli.go usage line /
// gate.go "have: npm, pypi, github, cargo, gem, go, docker, mcp").
var gateableEcosystems = map[string]bool{
	"npm": true, "pypi": true, "github": true, "cargo": true,
	"gem": true, "go": true, "docker": true, "mcp": true,
}

func FuzzParseInstallCommand(f *testing.F) {
	// --- Seed corpus: known-good branches (keep the fuzzer near real grammar) ---
	for _, s := range []string{
		"ls -la",
		"git status",
		"npm ci",
		"npm install --save-exact left-pad@1.3.0",
		"pip install requests==2.31.0",
		"pip install requests",
		"uv add httpx==0.27.0",
		"cargo install ripgrep",
		"gem install rails",
		"go get github.com/foo/bar@v1.2.3",
		"go install github.com/foo/bar@latest",
		"docker pull alpine@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5",
		"docker pull alpine:latest",
		"git clone https://github.com/golang/go.git",
		"gh repo clone golang/go",
		"claude mcp add some-server",
		"winget install Foo.Bar",
		"npx left-pad@1.3.0",
		"ls && npx left-pad@1.3.0",
	} {
		f.Add(s)
	}

	// --- Seed corpus: ADVERSARIAL TB1 bypass attempts (the crasher candidates) ---
	// Each of these is a class a prompt-injected agent (or a researcher writing
	// the day-2 PoC, gate-evasion-publication risk) would try. The contract is
	// that NONE crashes and NONE produces a silent ActionGate with a blank name.
	for _, s := range []string{
		// command substitution / shell expansion smuggling the package name
		"npm install $(echo left-pad)@1.0.0",
		"pip install `cat pkg.txt`",
		"npm install --save-exact ${PKG}",
		"npm install --save-exact $PKG@1.0.0",
		// nested / repeated shell wrappers
		"bash -c 'bash -c \"npm install evil\"'",
		"sh -c 'pip install requests'",
		"powershell -c 'npm ci'",
		// quoting tricks around the spec
		`npm install --save-exact "left-pad@1.0.0"`,
		`npm install --save-exact 'left'"-pad"@1.0.0`,
		// command-position confusion / verb buried mid-string
		"echo npm install evil && ls",
		"X=1 npm install --save-exact a@1",
		// separator floods (regex backtracking / index-math edge cases)
		"npm install@",
		";;;;;;;;;;npm install -E a@1",
		"&&||&&||npx a@1",
		"|||||||||||||",
		// trailing/leading control chars
		"npm install -E a@1;",
		"\n\n\nnpm ci\n\n",
		"\tnpm install -E a@1\t",
		// pathological at-signs / colons (docker + npm scope split math)
		"docker pull @@@@@@@@",
		"docker pull a:b:c:d@e:f@sha256:",
		"npm install -E @@@@@@",
		"npm install -E @scope/@scope/pkg@@@1",
		// go module case-escape + at-sign math
		"go get A!B!C@v1",
		"go install x@@@latest",
		// gh shorthand abuse (the deliberate-improvement branch)
		"gh repo clone ../../etc/passwd",
		"gh repo clone a/b/c/d",
		"gh repo clone -",
		// empty-ish / unicode / very long
		"",
		" ",
		"\x00\x00\x00",
		"npm install evil", // non-breaking spaces instead of ASCII spaces
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, cmd string) {
		pr := ParseInstallCommand(cmd)

		// Invariant 2: Action is in range.
		switch pr.Action {
		case ActionIgnore, ActionAllow, ActionBlock, ActionGate:
		default:
			t.Fatalf("parser returned out-of-range Action %d for %q — a switch on this would default-allow (bypass)", pr.Action, cmd)
		}

		if pr.Action == ActionGate {
			// Invariant 3: fail-closed — a gate result must name a real artifact.
			if trimmedEmpty(pr.Name) {
				t.Fatalf("ActionGate with blank Name for %q (eco=%q version=%q) — unparseable-pass bypass (§A.5). Must be ActionBlock fail-closed.", cmd, pr.Eco, pr.Version)
			}
			// Invariant 4: gate result names a dispatchable ecosystem.
			if !gateableEcosystems[pr.Eco] {
				t.Fatalf("ActionGate names unknown ecosystem %q for %q — engine would fail closed; parser bug", pr.Eco, cmd)
			}
		}

		// Invariant 5: determinism (no hidden state; same input → same action).
		if pr2 := ParseInstallCommand(cmd); pr2.Action != pr.Action {
			t.Fatalf("non-deterministic parse for %q: %d then %d", cmd, pr.Action, pr2.Action)
		}
	})
}

// trimmedEmpty reports whether s is empty after trimming ASCII whitespace —
// the same blankness test gateResult applies (strings.TrimSpace(name) == "").
func trimmedEmpty(s string) bool {
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', '\v', '\f':
		default:
			return false
		}
	}
	return true
}
