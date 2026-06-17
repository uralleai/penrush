// Package cli wires the PenRUSH internal engine packages into the four
// chunk-1 commands (init, check, override, stats). It is deliberately
// separated from cmd/penrush/main.go so the command surface is unit-testable
// without a process boundary (architecture §K test strategy).
//
// Design rules honored here:
//   - zero third-party deps (stdlib flag/fmt/os only) — A.2 dependency budget
//   - fail-closed: any internal error path defaults to BLOCK per the config's
//     on_internal_error (§C.6, §L-4); the top-level recover() in Run turns a
//     panic into an internal-error block, not a silent crash-bypass
//   - all I/O goes through an injectable Env so tests redirect stdout/stderr,
//     argv and the clock without touching real files or the network
//   - color: signal-amber accent only, suppressed when NO_COLOR is set or
//     stdout is not a TTY (plain text when piped)
package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/penrush/penrush/internal/registry"
)

// Version is the CLI version string. main.go may override it (ldflags) and it
// is mirrored into the registry User-Agent.
var Version = "0.1.0-dev"

// Exit codes (stable contract). 0 pass, 1 block, 2 usage/internal error.
//
// IMPORTANT — the Claude Code hook adapter does NOT use ExitBlock (=1): per the
// PreToolUse contract, exit 1 is NON-blocking (the tool call proceeds), so the
// hook path returns exit 0 + a deny JSON (primary) or ExitHookBlock (=2, the
// guaranteed block) for its fail-closed fallback. See hook.go.
const (
	ExitPass     = 0
	ExitBlock    = 1
	ExitUsageErr = 2
)

// Env is the injectable execution environment. Tests construct one pointing at
// a temp dir and buffers; main.go wires it to the real process.
type Env struct {
	Args   []string // args after the program name (os.Args[1:])
	Stdout io.Writer
	Stderr io.Writer
	Home   string // PenRUSH home dir; "" means resolve via penrushdir (PENRUSH_HOME or ~/.penrush)
	Now    func() time.Time
	// Color is the resolved accent decision (already accounts for NO_COLOR and
	// TTY). main.go computes it; tests usually leave it false.
	Color bool
	// NewClient builds the registry HTTP client. Tests inject a fixture-backed
	// client; production leaves it nil (real hardened client is used).
	NewClient func() *registry.Client
	// Resolvers, when non-nil, fully replaces the per-ecosystem resolver set.
	// This is the test seam: a test points resolvers at an httptest server (or
	// at a stub that always errors, to exercise the fail-closed path) without
	// any real network access. Production leaves it nil.
	Resolvers map[string]registry.Resolver
	// Stdin is the PreToolUse payload reader for `hook claude-code`. main.go
	// wires it to os.Stdin; tests supply a bytes.Reader. nil means no stdin
	// (the hook treats that as a parse failure → fail-closed).
	Stdin io.Reader
}

// stdin returns the injected stdin reader (nil when unset).
func (e *Env) stdin() io.Reader { return e.Stdin }

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// ANSI signal-amber accent (PenRUSH brand signal color). Used sparingly and
// only when e.Color is true.
const (
	ansiAmber = "\x1b[38;5;214m"
	ansiBold  = "\x1b[1m"
	ansiReset = "\x1b[0m"
)

func (e *Env) accent(s string) string {
	if !e.Color {
		return s
	}
	return ansiAmber + s + ansiReset
}

func (e *Env) bold(s string) string {
	if !e.Color {
		return s
	}
	return ansiBold + s + ansiReset
}

const usage = `penrush — don't rush to download. (supply-chain download gate)

Usage:
  penrush init                              create ~/.penrush/ (config, overrides, audit log)
  penrush check <ecosystem> <pkg>[@version]  run the gate against an artifact (dry-run; installs nothing)
  penrush check <ecosystem>:<pkg>[@version]  (FR-007 colon form — equivalent)
  penrush override add <key> --reason "..."  add an override (key = <ecosystem>:<artifact>)
  penrush stats                             local-only readout of the audit log (no network)
  penrush hook claude-code                  PreToolUse hook adapter (reads a payload on stdin)
  penrush version                           print version

Ecosystems in this build: npm, pypi, github, cargo, gem, go, docker, mcp
  - docker: pin by digest (image@sha256:...) to pass on any registry; tag-only
            Docker Hub images are age-gated; tag-only non-Hub images block.
  - mcp:    always approval-gated (registry is preview) — approve with override.

Global behavior:
  - fail-closed: an unreachable registry BLOCKS (never warn-and-pass)
  - no telemetry, no phone-home — everything stays in ~/.penrush/
  - NO_COLOR honored; output is plain when piped`

// Run dispatches to the subcommand and returns a process exit code. It NEVER
// panics out: a recovered panic becomes an internal-error block (§C.6) so a
// crashing gate cannot become a silent bypass.
func Run(e *Env) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(e.Stderr, "%s internal error (fail-closed): %v\n", e.accent("[penrush] BLOCK"), r)
			code = ExitBlock
		}
	}()

	if len(e.Args) == 0 {
		fmt.Fprintln(e.Stderr, usage)
		return ExitUsageErr
	}

	switch e.Args[0] {
	case "init":
		return runInit(e, e.Args[1:])
	case "check":
		return runCheck(e, e.Args[1:])
	case "override":
		return runOverride(e, e.Args[1:])
	case "stats":
		return runStats(e, e.Args[1:])
	case "hook":
		return runHook(e, e.Args[1:])
	case "version", "--version", "-v":
		fmt.Fprintf(e.Stdout, "penrush %s\n", Version)
		return ExitPass
	case "help", "--help", "-h":
		fmt.Fprintln(e.Stdout, usage)
		return ExitPass
	default:
		fmt.Fprintf(e.Stderr, "penrush: unknown command %q\n\n%s\n", e.Args[0], usage)
		return ExitUsageErr
	}
}
