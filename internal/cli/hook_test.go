package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/penrush/penrush/internal/registry"
)

// decodeHookDecision runs the hook with `command` on stdin and returns the
// emitted permissionDecision (or "" if the hook exited 2 / wrote no JSON).
func decodeHookDecision(t *testing.T, home string, command string, resolvers map[string]registry.Resolver) (decision string, exitCode int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	e := &Env{
		Args:      []string{"hook", "claude-code"},
		Stdout:    &out,
		Stderr:    &errb,
		Home:      home,
		Now:       clk(),
		Resolvers: resolvers,
		Stdin:     strings.NewReader(preToolUseJSON(command)),
	}
	exitCode = Run(e)
	stdout, stderr = out.String(), errb.String()
	if exitCode == ExitPass && strings.TrimSpace(stdout) != "" {
		var ho hookOutput
		if err := json.Unmarshal([]byte(stdout), &ho); err != nil {
			t.Fatalf("hook emitted non-JSON on exit 0 for %q: %v\nstdout: %s", command, err, stdout)
		}
		if ho.HookSpecificOutput.HookEventName != "PreToolUse" {
			t.Fatalf("hook JSON missing hookEventName=PreToolUse for %q: %s", command, stdout)
		}
		decision = ho.HookSpecificOutput.PermissionDecision
	}
	return decision, exitCode, stdout, stderr
}

func preToolUseJSON(command string) string {
	b, _ := json.Marshal(hookPayload{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
	})
	// Build the real nested shape (hookPayload's ToolInput is an embedded
	// struct, so marshal it directly via a map to be faithful to the wire form).
	m := map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": command},
	}
	bb, _ := json.Marshal(m)
	_ = b
	return string(bb)
}

// hookDecisionToAction maps a hook outcome to the {allow,block} vocabulary the
// parity corpus uses. A deny (exit 0) and an exit-2 fallback are both "block";
// an allow is "allow"; an "ask" is treated as a non-block (override UX) — none
// of the corpus cases expect ask, so it surfaces as a failure if it appears.
func hookDecisionToAction(decision string, exitCode int) string {
	if exitCode == ExitHookBlock {
		return "block"
	}
	switch decision {
	case decisionAllow:
		return "allow"
	case decisionDeny:
		return "block"
	case decisionAsk:
		return "ask"
	default:
		return "ask" // unexpected — fails the assertion
	}
}

// ---- The 22-case parity corpus (architecture §K Parity row) ----------------
//
// Ported from the reference oracle's suite
// (~/.claude/security/test_supply_chain_gate.py). Each case is a raw shell
// command + its expected {allow,block} verdict. The corpus exercises every
// parser branch: non-install passthrough, lockfile-frozen allow, /lock file
// pin-violation block, age-gated allow/block via the engine, docker digest vs
// tag, go @latest, claude mcp, system package managers, ephemeral exec verbs,
// command-position anchoring, and the unparseable-fails-closed principle.
//
// "Aged" packages (resolver returns a 400-day-old publish time) clear the
// 14-day cool-down; "fresh" (2-day) ones block; an erroring resolver is the
// fail-closed path; ErrNotFound is the dependency-confusion block.

type parityCase struct {
	command string
	want    string // "allow" | "block"
	label   string
}

var parityCorpus = []parityCase{
	// 1-3: non-install commands pass straight through (no registry call).
	{"ls -la", "allow", "plain ls"},
	{"git status", "allow", "git status"},
	{`python -c "print('the word npx appears here')"`, "allow", "npx inside python -c string (cmd-pos anchor)"},

	// 4-7: lockfile-frozen modes ALLOW by structure.
	{"npm ci", "allow", "npm ci frozen"},
	{"uv sync --frozen", "allow", "uv frozen sync"},
	{"pnpm install --frozen-lockfile", "allow", "pnpm frozen"},
	{"poetry install", "allow", "poetry default lockfile"},

	// 8-9: /lock file violations BLOCK by structure (no registry call).
	{"pip install -r requirements.txt", "block", "pip -r without --require-hashes"},
	{"pip install requests", "block", "pip without == pin"},

	// 10-11: aged + pinned packages ALLOW via the age gate engine.
	{"npm install --save-exact left-pad@1.3.0", "allow", "npm aged + --save-exact"},
	{"pip install requests==2.31.0", "allow", "pip pinned + aged"},

	// 12: a fresh (under-cooldown) pinned package BLOCKS via the engine.
	{"pip install shiny==0.0.1", "block", "pip pinned but fresh -> age block"},

	// 13-14: docker digest pin ALLOWS; tag-only Docker Hub fresh BLOCKS.
	{"docker pull alpine@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5", "allow", "docker digest-pinned"},
	{"docker pull alpine:latest", "block", "docker tag-only fresh -> block"},

	// 15: go install @latest BLOCKS by structure.
	{"go install github.com/foo/bar@latest", "block", "go @latest forbidden"},

	// 16: claude mcp add BLOCKS (approval-gated via the engine's MCP resolver).
	{"claude mcp add some-server", "block", "claude mcp add approval-gated"},

	// 17-18: system / distro package managers BLOCK by structure.
	{"winget install Foo.Bar", "block", "winget approval"},
	{"brew install jq", "block", "brew approval"},

	// 19: ephemeral exec verb with an aged pkg ALLOWS via the engine.
	{"npx left-pad@1.3.0", "allow", "npx aged pkg"},

	// 20: ephemeral exec with an unverifiable version -> fail-closed BLOCK.
	{"npx left-pad@99.99.99-doesnotexist", "block", "npx unverifiable -> fail-closed"},

	// 21: local-file npx is NOT an install -> allow.
	{"npx ./scripts/local-tool.js", "allow", "npx local file"},

	// 22: verb at a command-position after && still fires; aged pkg passes.
	{"ls && npx left-pad@1.3.0", "allow", "npx after && (aged pkg)"},
}

// parityResolvers returns a resolver set that makes the corpus deterministic
// and OFFLINE: known-aged artifacts resolve old, fresh ones resolve recent,
// and the synthetic "doesnotexist" version errors (fail-closed). The SAME set
// is used for the CLI `check` path and the hook path, so any divergence is a
// real parity bug, not a fixture artifact.
func parityResolvers() map[string]registry.Resolver {
	aged := fixedNow.AddDate(0, 0, -400)
	fresh := fixedNow.AddDate(0, 0, -2)
	return map[string]registry.Resolver{
		"npm":    parityNPM{aged: aged},
		"pypi":   parityPyPI{aged: aged, fresh: fresh},
		"docker": parityDocker{fresh: fresh},
		"go":     stubResolver{eco: "go", published: aged},
		"cargo":  stubResolver{eco: "cargo", published: aged},
		"gem":    stubResolver{eco: "gem", published: aged},
		"github": stubResolver{eco: "github", published: aged},
		"mcp":    parityMCP{},
	}
}

// parityNPM: left-pad@1.3.0 is aged; the synthetic doesnotexist version errors.
type parityNPM struct{ aged time.Time }

func (parityNPM) Ecosystem() string { return "npm" }
func (r parityNPM) Resolve(_ context.Context, name, version string) (*registry.Resolution, error) {
	if strings.Contains(version, "doesnotexist") {
		return nil, errors.New("npm: version not found")
	}
	return &registry.Resolution{PublishedAt: r.aged, SourceURL: "https://npm/" + name, Confidence: "version-publish-time"}, nil
}

// parityPyPI: requests is aged; "shiny" is fresh (under cooldown).
type parityPyPI struct{ aged, fresh time.Time }

func (parityPyPI) Ecosystem() string { return "pypi" }
func (r parityPyPI) Resolve(_ context.Context, name, _ string) (*registry.Resolution, error) {
	pub := r.aged
	if name == "shiny" {
		pub = r.fresh
	}
	return &registry.Resolution{PublishedAt: pub, SourceURL: "https://pypi/" + name, Confidence: "version-publish-time"}, nil
}

// parityDocker mirrors the real docker resolver's control: a digest pin passes
// (distant-past publish), a tag-only Hub reference resolves to the fresh time.
type parityDocker struct{ fresh time.Time }

func (parityDocker) Ecosystem() string { return "docker" }
func (r parityDocker) Resolve(_ context.Context, name, version string) (*registry.Resolution, error) {
	if strings.HasPrefix(version, "sha256:") {
		return &registry.Resolution{PublishedAt: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), SourceURL: "docker-ref", Confidence: "digest-pinned"}, nil
	}
	return &registry.Resolution{PublishedAt: r.fresh, SourceURL: "https://hub/" + name, Confidence: "tag-last-pushed"}, nil
}

// parityMCP always returns ErrApprovalRequired (the real MCP resolver's
// posture): an MCP add is approval-gated -> block.
type parityMCP struct{}

func (parityMCP) Ecosystem() string { return "mcp" }
func (parityMCP) Resolve(_ context.Context, name, _ string) (*registry.Resolution, error) {
	return nil, registry.ErrApprovalRequired
}

// TestParityCorpus is the core chunk-3 acceptance: for every corpus command the
// HOOK path must reach the same {allow,block} verdict the reference oracle
// expects. For the cases that route through the age gate engine (ActionGate),
// this is true parity-by-construction because the hook calls the exact same
// gate.Engine.CheckGate1 the `check` subcommand calls; the test additionally
// cross-checks those against the live CLI `check` verdict (see
// TestHookCheckVerdictParity).
func TestParityCorpus(t *testing.T) {
	home := initHome(t)
	for _, tc := range parityCorpus {
		t.Run(tc.label, func(t *testing.T) {
			decision, code, stdout, stderr := decodeHookDecision(t, home, tc.command, parityResolvers())
			got := hookDecisionToAction(decision, code)
			if got != tc.want {
				t.Fatalf("hook verdict for %q = %q (decision=%q exit=%d), want %q\nstdout: %s\nstderr: %s",
					tc.command, got, decision, code, tc.want, stdout, stderr)
			}
		})
	}
}

// TestHookCheckVerdictParity proves the load-bearing parity property directly:
// for every ActionGate command, the hook's permissionDecision matches the CLI
// `check` exit code on the SAME parsed (eco,name,version) with the SAME
// resolver set. Same engine, same inputs => same verdict.
func TestHookCheckVerdictParity(t *testing.T) {
	gateCommands := []string{
		"npm install --save-exact left-pad@1.3.0",
		"pip install requests==2.31.0",
		"pip install shiny==0.0.1",
		"docker pull alpine@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5",
		"docker pull alpine:latest",
		"npx left-pad@1.3.0",
		"npx left-pad@99.99.99-doesnotexist",
		"cargo install ripgrep",
		"gem install rails",
	}
	for _, cmd := range gateCommands {
		t.Run(cmd, func(t *testing.T) {
			pr := ParseInstallCommand(cmd)
			if pr.Action != ActionGate {
				t.Skipf("%q is not an ActionGate command (action=%d) — covered by the structural corpus", cmd, pr.Action)
			}
			home := initHome(t)

			// CLI `check` path.
			var cout, cerr bytes.Buffer
			chk := &Env{
				Args:   []string{"check", pr.Eco, joinSpec(pr.Name, pr.Version)},
				Stdout: &cout, Stderr: &cerr, Home: home, Now: clk(),
				Resolvers: parityResolvers(),
			}
			checkExit := Run(chk)
			checkAction := "allow"
			if checkExit == ExitBlock {
				checkAction = "block"
			}

			// Hook path (fresh home so the audit/cache state is independent).
			home2 := initHome(t)
			decision, code, _, _ := decodeHookDecision(t, home2, cmd, parityResolvers())
			hookAction := hookDecisionToAction(decision, code)

			if hookAction != checkAction {
				t.Fatalf("PARITY VIOLATION for %q: hook=%q vs check=%q (hook decision=%q exit=%d, check exit=%d)",
					cmd, hookAction, checkAction, decision, code, checkExit)
			}
		})
	}
}

func joinSpec(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

// TestHookEmitsValidPermissionDecisionJSON: an allow and a deny both ride exit
// 0 with a well-formed hookSpecificOutput envelope.
func TestHookEmitsValidPermissionDecisionJSON(t *testing.T) {
	home := initHome(t)

	// Allow case (aged pkg).
	dec, code, stdout, _ := decodeHookDecision(t, home, "npx left-pad@1.3.0", parityResolvers())
	if code != ExitPass || dec != decisionAllow {
		t.Fatalf("aged npx: want exit 0 + allow, got exit=%d decision=%q\n%s", code, dec, stdout)
	}
	if !strings.Contains(stdout, `"hookEventName":"PreToolUse"`) || !strings.Contains(stdout, `"permissionDecision":"allow"`) {
		t.Fatalf("allow JSON malformed: %s", stdout)
	}

	// Deny case (fresh pkg) — exit 0 + deny JSON (NOT exit 2; the primary path).
	dec, code, stdout, _ = decodeHookDecision(t, home, "pip install shiny==0.0.1", parityResolvers())
	if code != ExitPass || dec != decisionDeny {
		t.Fatalf("fresh pip: want exit 0 + deny, got exit=%d decision=%q\n%s", code, dec, stdout)
	}
	if !strings.Contains(stdout, `"permissionDecision":"deny"`) {
		t.Fatalf("deny JSON malformed: %s", stdout)
	}
	// The deny reason must carry the override path (brief requirement).
	if !strings.Contains(stdout, "penrush override add") {
		t.Fatalf("deny reason must print the override path, got: %s", stdout)
	}
}

// TestHookFailsClosedOnUnparseableStdin: malformed JSON on stdin must BLOCK via
// exit 2 (the guaranteed block), NEVER allow. The reference Python hook fails
// OPEN here; the product diverges to fail-closed (§C.6).
func TestHookFailsClosedOnUnparseableStdin(t *testing.T) {
	home := initHome(t)
	for _, payload := range []string{"", "not json at all", `{"tool_name": "Bash", "tool_input": {`} {
		var out, errb bytes.Buffer
		e := &Env{
			Args:   []string{"hook", "claude-code"},
			Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
			Stdin: strings.NewReader(payload),
		}
		code := Run(e)
		if code != ExitHookBlock {
			t.Fatalf("unparseable stdin %q: exit = %d, want %d (fail-closed block)\nstderr: %s", payload, code, ExitHookBlock, errb.String())
		}
		if !strings.Contains(errb.String(), "BLOCK") {
			t.Fatalf("unparseable stdin %q: expected a BLOCK message on stderr, got: %s", payload, errb.String())
		}
	}
}

// TestHookAllowsNonBashTool: a non-Bash tool call is allowed (the gate has no
// opinion) — exit 0 + allow.
func TestHookAllowsNonBashTool(t *testing.T) {
	home := initHome(t)
	var out, errb bytes.Buffer
	m := map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Edit",
		"tool_input":      map[string]any{"file_path": "/x", "command": "irrelevant"},
	}
	raw, _ := json.Marshal(m)
	e := &Env{
		Args:   []string{"hook", "claude-code"},
		Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
		Stdin: bytes.NewReader(raw),
	}
	if code := Run(e); code != ExitPass {
		t.Fatalf("non-Bash tool: exit = %d, want %d", code, ExitPass)
	}
	if !strings.Contains(out.String(), `"permissionDecision":"allow"`) {
		t.Fatalf("non-Bash tool should allow, got: %s", out.String())
	}
}

// panicResolver panics inside Resolve to exercise the §C.6 panic-recovery ->
// block path.
type panicResolver struct{ eco string }

func (p panicResolver) Ecosystem() string { return p.eco }
func (panicResolver) Resolve(context.Context, string, string) (*registry.Resolution, error) {
	panic("synthetic resolver panic")
}

// TestHookPanicRecoversToBlock: a panic anywhere on the gate path must convert
// to a BLOCK (exit 2), honoring on_internal_error=block (the default). A
// crashing gate must never become a silent bypass (§C.6).
func TestHookPanicRecoversToBlock(t *testing.T) {
	home := initHome(t)
	var out, errb bytes.Buffer
	e := &Env{
		Args:   []string{"hook", "claude-code"},
		Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
		Resolvers: map[string]registry.Resolver{"npm": panicResolver{eco: "npm"}},
		Stdin:     strings.NewReader(preToolUseJSON("npm install --save-exact left-pad@1.3.0")),
	}
	code := Run(e)
	if code != ExitHookBlock {
		t.Fatalf("panic on gate path: exit = %d, want %d (fail-closed block)\nstdout: %s\nstderr: %s", code, ExitHookBlock, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "internal error") || !strings.Contains(errb.String(), "fail-closed") {
		t.Fatalf("panic should yield a fail-closed internal-error block, got stderr: %s", errb.String())
	}
}

// TestHookUsage: `penrush hook` with no surface, or an unknown surface, is a
// usage error (exit 2) — NOT a silent pass.
func TestHookUsage(t *testing.T) {
	for _, args := range [][]string{
		{"hook"},
		{"hook", "bogus-surface"},
	} {
		e, _, errb := newEnv(t, args...)
		if code := Run(e); code != ExitUsageErr {
			t.Fatalf("args %v: exit = %d, want %d", args, code, ExitUsageErr)
		}
		if !strings.Contains(errb.String(), "claude-code") {
			t.Fatalf("args %v: expected usage hint, got: %s", args, errb.String())
		}
	}
}
