package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/penrush/penrush/internal/penrushdir"
	"github.com/penrush/penrush/internal/registry"
)

// fixedNow pins the clock so age math is deterministic.
var fixedNow = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

func clk() func() time.Time { return func() time.Time { return fixedNow } }

// stubResolver is an offline registry.Resolver. It returns a fixed publish
// time, or a transport-style error to exercise the fail-closed path. No
// network, no httptest — fully hermetic.
type stubResolver struct {
	eco       string
	published time.Time
	err       error
}

func (s stubResolver) Ecosystem() string { return s.eco }
func (s stubResolver) Resolve(_ context.Context, name, version string) (*registry.Resolution, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &registry.Resolution{
		PublishedAt: s.published,
		SourceURL:   "https://stub.example/" + name,
		Confidence:  "version-publish-time",
	}, nil
}

// newEnv builds a test Env rooted at a temp home, capturing stdout/stderr.
func newEnv(t *testing.T, args ...string) (*Env, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, errb bytes.Buffer
	e := &Env{
		Args:   args,
		Stdout: &out,
		Stderr: &errb,
		Home:   t.TempDir(),
		Now:    clk(),
		Color:  false,
	}
	return e, &out, &errb
}

func TestInitCreatesTreeIdempotently(t *testing.T) {
	e, out, _ := newEnv(t, "init")
	if code := Run(e); code != ExitPass {
		t.Fatalf("init exit = %d, want %d", code, ExitPass)
	}
	for _, p := range []string{
		penrushdir.ConfigPath(e.Home),
		penrushdir.OverridesPath(e.Home),
		penrushdir.AuditPath(e.Home),
		penrushdir.CacheDir(e.Home),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s to exist after init: %v", p, err)
		}
	}
	if !strings.Contains(out.String(), "created") {
		t.Fatalf("first init should report created artifacts, got:\n%s", out.String())
	}

	// Capture config bytes (incl. the random cache HMAC key) to prove the
	// second run preserves them rather than regenerating.
	cfgBefore, err := os.ReadFile(penrushdir.ConfigPath(e.Home))
	if err != nil {
		t.Fatal(err)
	}

	// Second run: idempotent — no error, artifacts kept.
	e2, out2, _ := newEnv(t, "init")
	e2.Home = e.Home // same home
	if code := Run(e2); code != ExitPass {
		t.Fatalf("second init exit = %d, want %d", code, ExitPass)
	}
	if !strings.Contains(out2.String(), "already present (kept)") {
		t.Fatalf("second init should keep existing artifacts, got:\n%s", out2.String())
	}
	cfgAfter, err := os.ReadFile(penrushdir.ConfigPath(e.Home))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cfgBefore, cfgAfter) {
		t.Fatal("idempotent init must not rewrite config.json (cache HMAC key must stay stable)")
	}
}

// initHome runs init into a fresh temp home and returns it.
func initHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	e := &Env{Args: []string{"init"}, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Home: home, Now: clk()}
	if code := Run(e); code != ExitPass {
		t.Fatalf("init setup failed: %d", code)
	}
	// The v0.2.0 production default is Gate 8 ON, which would build the live
	// payload scanner in every check-path test that injects no Gate8Scanner.
	// The Gate-1 suite is not about content analysis — opt Gate 8 out here so
	// those tests stay network-free. Gate-8 tests opt back in explicitly.
	setGate8(t, home, false)
	return home
}

func TestCheckPassesOnOldPackage(t *testing.T) {
	home := initHome(t)
	var out, errb bytes.Buffer
	e := &Env{
		Args:   []string{"check", "npm", "left-pad@1.3.0"},
		Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
		Resolvers: map[string]registry.Resolver{
			// published 400 days before fixedNow -> well past the 14-day gate
			"npm": stubResolver{eco: "npm", published: fixedNow.AddDate(0, 0, -400)},
		},
	}
	if code := Run(e); code != ExitPass {
		t.Fatalf("check old pkg exit = %d, want %d (pass)\nstdout:%s\nstderr:%s", code, ExitPass, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "[penrush] PASS") {
		t.Fatalf("expected PASS verdict, got:\n%s", out.String())
	}
	// Audit entry must have been written.
	raw, _ := os.ReadFile(penrushdir.AuditPath(home))
	if !strings.Contains(string(raw), `"decision":"pass"`) {
		t.Fatalf("expected a pass audit entry, got:\n%s", raw)
	}
}

func TestCheckBlocksOnRecentPackage(t *testing.T) {
	home := initHome(t)
	var out, errb bytes.Buffer
	e := &Env{
		Args:   []string{"check", "pypi", "shiny-new-thing@0.0.1"},
		Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
		Resolvers: map[string]registry.Resolver{
			// published 2 days ago -> under the 14-day cool-down
			"pypi": stubResolver{eco: "pypi", published: fixedNow.AddDate(0, 0, -2)},
		},
	}
	if code := Run(e); code != ExitBlock {
		t.Fatalf("check recent pkg exit = %d, want %d (block)", code, ExitBlock)
	}
	o := out.String()
	if !strings.Contains(o, "[penrush] BLOCK") {
		t.Fatalf("expected BLOCK verdict, got:\n%s", o)
	}
	// Override path must be printed on BLOCK (brief requirement).
	if !strings.Contains(o, "penrush override add pypi:shiny-new-thing --reason") {
		t.Fatalf("BLOCK must print the override path, got:\n%s", o)
	}
}

// FR-003 / NFR-002: an unreachable registry BLOCKS (fail-closed), never passes.
func TestCheckFailsClosedOnUnreachableRegistry(t *testing.T) {
	home := initHome(t)
	var out, errb bytes.Buffer
	e := &Env{
		Args:   []string{"check", "npm", "anything"},
		Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
		Resolvers: map[string]registry.Resolver{
			"npm": stubResolver{eco: "npm", err: errors.New("dial tcp: connection refused")},
		},
	}
	if code := Run(e); code != ExitBlock {
		t.Fatalf("unreachable registry exit = %d, want %d (fail-closed block)", code, ExitBlock)
	}
	o := out.String()
	if !strings.Contains(o, "[penrush] BLOCK") || !strings.Contains(strings.ToLower(o), "cannot verify") {
		t.Fatalf("expected fail-closed 'cannot verify' BLOCK, got:\n%s", o)
	}
	// The fail-closed verdict must be recorded as a block in the audit log.
	raw, _ := os.ReadFile(penrushdir.AuditPath(home))
	if !strings.Contains(string(raw), `"decision":"block"`) {
		t.Fatalf("fail-closed must be audited as a block, got:\n%s", raw)
	}
}

// A 404 from the registry is its own red flag (dependency-confusion posture)
// and must block with a distinct message.
func TestCheckBlocksOnNotFound(t *testing.T) {
	home := initHome(t)
	var out, errb bytes.Buffer
	e := &Env{
		Args:   []string{"check", "npm", "no-such-pkg-xyz"},
		Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
		Resolvers: map[string]registry.Resolver{
			"npm": stubResolver{eco: "npm", err: registry.ErrNotFound},
		},
	}
	if code := Run(e); code != ExitBlock {
		t.Fatalf("not-found exit = %d, want %d", code, ExitBlock)
	}
	if !strings.Contains(out.String(), "not found") {
		t.Fatalf("expected a not-found block message, got:\n%s", out.String())
	}
}

// FR-004: override then re-check passes; the override-used verdict is audited.
func TestOverrideAddThenCheckPasses(t *testing.T) {
	home := initHome(t)

	// Add an override for the recent package.
	var aout, aerr bytes.Buffer
	add := &Env{
		Args:   []string{"override", "add", "pypi:shiny-new-thing", "--reason", "manually reviewed the source"},
		Stdout: &aout, Stderr: &aerr, Home: home, Now: clk(),
	}
	if code := Run(add); code != ExitPass {
		t.Fatalf("override add exit = %d, want %d\nstderr:%s", code, ExitPass, aerr.String())
	}
	if _, err := os.Stat(penrushdir.OverridesPath(home)); err != nil {
		t.Fatalf("overrides.json missing after add: %v", err)
	}

	// Re-check the still-recent package: the override makes it pass.
	var cout, cerr bytes.Buffer
	chk := &Env{
		Args:   []string{"check", "pypi", "shiny-new-thing@0.0.1"},
		Stdout: &cout, Stderr: &cerr, Home: home, Now: clk(),
		Resolvers: map[string]registry.Resolver{
			"pypi": stubResolver{eco: "pypi", published: fixedNow.AddDate(0, 0, -2)},
		},
	}
	if code := Run(chk); code != ExitPass {
		t.Fatalf("override'd check exit = %d, want %d (override pass)\nstdout:%s", code, ExitPass, cout.String())
	}
	if !strings.Contains(cout.String(), "[penrush] OVERRIDE") {
		t.Fatalf("expected OVERRIDE verdict, got:\n%s", cout.String())
	}
}

// The override key may appear before OR after the flags (stdlib flag would
// otherwise choke on key-first ordering).
func TestOverrideAddOrderIndependent(t *testing.T) {
	for _, args := range [][]string{
		{"override", "add", "npm:foo", "--reason", "key first"},
		{"override", "add", "--reason", "flag first", "npm:bar"},
		{"override", "add", "--reason=equals form", "npm:baz"},
	} {
		home := initHome(t)
		var out, errb bytes.Buffer
		e := &Env{Args: args, Stdout: &out, Stderr: &errb, Home: home, Now: clk()}
		if code := Run(e); code != ExitPass {
			t.Fatalf("args %v exit = %d, want %d\nstderr:%s", args, code, ExitPass, errb.String())
		}
		if !strings.Contains(out.String(), "override added") {
			t.Fatalf("args %v: expected success, got:\n%s", args, out.String())
		}
	}
}

func TestOverrideAddRejectsWildcardKey(t *testing.T) {
	home := initHome(t)
	var out, errb bytes.Buffer
	e := &Env{Args: []string{"override", "add", "npm:*", "--reason", "x"}, Stdout: &out, Stderr: &errb, Home: home, Now: clk()}
	if code := Run(e); code != ExitUsageErr {
		t.Fatalf("wildcard key exit = %d, want %d", code, ExitUsageErr)
	}
	if !strings.Contains(errb.String(), "wildcard") {
		t.Fatalf("expected wildcard rejection, got:\n%s", errb.String())
	}
}

func TestOverrideAddRequiresReason(t *testing.T) {
	home := initHome(t)
	var out, errb bytes.Buffer
	e := &Env{
		Args:   []string{"override", "add", "npm:foo"},
		Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
	}
	if code := Run(e); code != ExitUsageErr {
		t.Fatalf("override add without reason exit = %d, want %d", code, ExitUsageErr)
	}
	if !strings.Contains(errb.String(), "--reason is mandatory") {
		t.Fatalf("expected mandatory-reason error, got:\n%s", errb.String())
	}
}

// stats must read the audit log with NO network. We assert that by giving the
// Env no resolvers at all and a real (would-fail) client is never constructed
// because stats never calls resolvers().
func TestStatsReadsAuditLogWithoutNetwork(t *testing.T) {
	home := initHome(t)

	// Produce a couple of decisions via stub-backed checks first.
	for _, tc := range []struct {
		pkg     string
		ageDays int
	}{
		{"old-one@1.0.0", -400}, // pass
		{"new-one@0.1.0", -1},   // block
	} {
		e := &Env{
			Args:   []string{"check", "npm", tc.pkg},
			Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Home: home, Now: clk(),
			Resolvers: map[string]registry.Resolver{
				"npm": stubResolver{eco: "npm", published: fixedNow.AddDate(0, 0, tc.ageDays)},
			},
		}
		Run(e)
	}

	// Now stats — note: NO Resolvers and NO NewClient. If stats touched the
	// network it would have to build a client; it must not.
	var out, errb bytes.Buffer
	st := &Env{Args: []string{"stats"}, Stdout: &out, Stderr: &errb, Home: home, Now: clk()}
	if code := Run(st); code != ExitPass {
		t.Fatalf("stats exit = %d, want %d\nstderr:%s", code, ExitPass, errb.String())
	}
	o := out.String()
	for _, want := range []string{"gate checks:        2", "passes:             1", "blocks:             1", "chain integrity:    OK"} {
		if !strings.Contains(o, want) {
			t.Fatalf("stats missing %q, got:\n%s", want, o)
		}
	}
}

func TestStatsOnFreshHome(t *testing.T) {
	home := initHome(t)
	var out, errb bytes.Buffer
	st := &Env{Args: []string{"stats"}, Stdout: &out, Stderr: &errb, Home: home, Now: clk()}
	if code := Run(st); code != ExitPass {
		t.Fatalf("stats on fresh home exit = %d, want %d", code, ExitPass)
	}
	if !strings.Contains(out.String(), "gate checks:        0") {
		t.Fatalf("fresh home should show zero checks, got:\n%s", out.String())
	}
}

func TestParseCheckArgs(t *testing.T) {
	cases := []struct {
		name              string
		args              []string
		wantEco, wantName string
		wantVer           string
		wantErr           bool
	}{
		{"two-arg-versioned", []string{"npm", "left-pad@1.3.0"}, "npm", "left-pad", "1.3.0", false},
		{"two-arg-noversion", []string{"pypi", "requests"}, "pypi", "requests", "", false},
		{"colon-form", []string{"npm:left-pad@1.3.0"}, "npm", "left-pad", "1.3.0", false},
		{"scoped-npm-two-arg", []string{"npm", "@types/node@20.11.5"}, "npm", "@types/node", "20.11.5", false},
		{"scoped-npm-noversion", []string{"npm", "@types/node"}, "npm", "@types/node", "", false},
		{"github-owner-repo", []string{"github", "golang/go"}, "github", "golang/go", "", false},
		{"uppercase-eco-normalized", []string{"NPM", "left-pad"}, "npm", "left-pad", "", false},
		{"unknown-eco", []string{"maven", "junit"}, "", "", "", true},
		{"no-args", []string{}, "", "", "", true},
		{"too-many-args", []string{"npm", "a", "b"}, "", "", "", true},
		{"flag-rejected", []string{"npm", "--force", "x"}, "", "", "", true},
		{"empty-colon", []string{"npm:"}, "", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eco, name, ver, err := parseCheckArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %v, got (%q,%q,%q)", tc.args, eco, name, ver)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %v: %v", tc.args, err)
			}
			if eco != tc.wantEco || name != tc.wantName || ver != tc.wantVer {
				t.Fatalf("parse %v = (%q,%q,%q), want (%q,%q,%q)", tc.args, eco, name, ver, tc.wantEco, tc.wantName, tc.wantVer)
			}
		})
	}
}

func TestUnknownCommand(t *testing.T) {
	e, _, errb := newEnv(t, "frobnicate")
	if code := Run(e); code != ExitUsageErr {
		t.Fatalf("unknown command exit = %d, want %d", code, ExitUsageErr)
	}
	if !strings.Contains(errb.String(), "unknown command") {
		t.Fatalf("expected unknown-command message, got:\n%s", errb.String())
	}
}

func TestVersionCommand(t *testing.T) {
	e, out, _ := newEnv(t, "version")
	if code := Run(e); code != ExitPass {
		t.Fatalf("version exit = %d, want %d", code, ExitPass)
	}
	if !strings.Contains(out.String(), "penrush") {
		t.Fatalf("version output missing program name, got:\n%s", out.String())
	}
}

// TestVersionCommandCommitStamp pins the release-build behavior: when the commit
// is stamped (ldflags at release time), `version` surfaces it; when unstamped
// ("unknown"/empty, a local/dev build), it is omitted. Reproducible-build-safe
// stamps only (architecture §H.1) — no build timestamp is ever embedded.
func TestVersionCommandCommitStamp(t *testing.T) {
	origV, origC := Version, Commit
	t.Cleanup(func() { Version, Commit = origV, origC })

	cases := []struct {
		name       string
		version    string
		commit     string
		wantSubstr string
		notSubstr  string
	}{
		{"stamped", "v9.9.9", "abcdef1234567890", "penrush v9.9.9 (abcdef1234567890)", ""},
		{"unstamped-unknown", "v9.9.9", "unknown", "penrush v9.9.9", "("},
		{"unstamped-empty", "v9.9.9", "", "penrush v9.9.9", "("},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			Version, Commit = c.version, c.commit
			e, out, _ := newEnv(t, "version")
			if code := Run(e); code != ExitPass {
				t.Fatalf("version exit = %d, want %d", code, ExitPass)
			}
			got := strings.TrimSpace(out.String())
			if !strings.Contains(got, c.wantSubstr) {
				t.Fatalf("version output = %q, want substring %q", got, c.wantSubstr)
			}
			if c.notSubstr != "" && strings.Contains(got, c.notSubstr) {
				t.Fatalf("version output = %q, must not contain %q", got, c.notSubstr)
			}
		})
	}
}

// D-12 §5-B: the LMO-cleared capability qualifier must be present, VERBATIM, in
// the user-facing CLI output so the material limitation (not a malware scanner,
// not a guarantee) rides every channel — including package-manager installs that
// never see the site or the ToS checkbox. Assert both surfaces: `init` and the
// help/usage banner. The exact string is locked; paraphrase = LMO re-review (D-16).
func TestCapabilityNoticeVerbatim(t *testing.T) {
	const want = "PenRUSH gates risky installs and raises attacker cost — it is not a malware scanner and not a guarantee. `penrush --license` for AS-IS terms."

	// The exported constant itself must be byte-for-byte the cleared text.
	if CapabilityNotice != want {
		t.Fatalf("CapabilityNotice drifted from the LMO D-12 §5-B verbatim text:\n got: %q\nwant: %q", CapabilityNotice, want)
	}

	// Surface 1 — `penrush init` prints it.
	einit, outInit, _ := newEnv(t, "init")
	if code := Run(einit); code != ExitPass {
		t.Fatalf("init exit = %d, want %d", code, ExitPass)
	}
	if !strings.Contains(outInit.String(), want) {
		t.Fatalf("penrush init must print the D-12 capability qualifier verbatim, got:\n%s", outInit.String())
	}

	// Surface 2 — the help/usage banner carries it (so `penrush help` / no-args do too).
	ehelp, outHelp, _ := newEnv(t, "help")
	if code := Run(ehelp); code != ExitPass {
		t.Fatalf("help exit = %d, want %d", code, ExitPass)
	}
	if !strings.Contains(outHelp.String(), want) {
		t.Fatalf("penrush help must carry the D-12 capability qualifier verbatim, got:\n%s", outHelp.String())
	}

	// Negative guard: the FORBIDDEN unqualified overclaim must never appear in
	// CLI output (D-12 §3.3).
	for _, surface := range []string{outInit.String(), outHelp.String()} {
		if strings.Contains(strings.ToLower(surface), "blocks supply-chain attacks") {
			t.Fatalf("FORBIDDEN overclaim 'blocks supply-chain attacks' present in CLI output:\n%s", surface)
		}
	}
}

// NO_COLOR / non-TTY behavior is decided in main.colorEnabled, but the cli
// accent helpers must produce plain output when Color is false. Pin it so a
// piped check is greppable.
func TestNoColorWhenColorDisabled(t *testing.T) {
	e := &Env{Color: false}
	if got := e.accent("X"); got != "X" {
		t.Fatalf("accent must be plain when Color=false, got %q", got)
	}
	if strings.Contains(e.bold("Y"), "\x1b[") {
		t.Fatalf("bold must not emit ANSI when Color=false, got %q", e.bold("Y"))
	}
}

// Sanity: the home resolution test seam writes only under the temp dir.
func TestHomeStaysInTempDir(t *testing.T) {
	home := initHome(t)
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected artifacts under temp home")
	}
	// Defensive: the audit path is inside home.
	if !strings.HasPrefix(penrushdir.AuditPath(home), filepath.Clean(home)) {
		t.Fatalf("audit path %q escaped home %q", penrushdir.AuditPath(home), home)
	}
}
