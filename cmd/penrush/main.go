// Command penrush is the PenRUSH supply-chain download gate CLI.
//
// It is a thin shell over internal/cli: it builds the real execution
// environment (process argv, stdio, clock, color decision) and delegates to
// cli.Run, whose exit code becomes the process exit code. All command logic
// lives in internal/cli so it is unit-testable without a process boundary.
//
// Zero third-party dependencies (architecture §A.2). Zero telemetry, zero
// phone-home (§E.2 / NFR-003).
package main

import (
	"os"

	"github.com/penrush/penrush/internal/cli"
)

// version and commit are stamped at build time via -ldflags. Both inputs are
// deterministic for a given release tag (the tag string, and the commit it
// points at), so embedding them does NOT compromise the reproducible build
// (architecture §H.1) — unlike a build timestamp, which is deliberately NOT
// embedded for exactly that reason. The release pipeline stamps these in
// .slsa-goreleaser.yml; local reproducible-build verification uses the same
// ldflags (see build.sh / make verify-reproducible).
//
//	go build -trimpath -ldflags "-s -w -buildid= -X main.version=v0.1.0 -X main.commit=<sha>" ./cmd/penrush
var (
	version = "0.1.0-dev"
	commit  = "unknown"
)

func main() {
	cli.Version = version
	cli.Commit = commit

	env := &cli.Env{
		Args:   os.Args[1:],
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Stdin:  os.Stdin, // PreToolUse payload for `hook claude-code`
		Color:  colorEnabled(),
	}
	os.Exit(cli.Run(env))
}

// colorEnabled decides whether to emit ANSI accents. It honors NO_COLOR (any
// non-empty value disables color, per the no-color.org convention) and only
// enables color when stdout is a character device (a terminal) — piped or
// redirected output stays plain.
func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
