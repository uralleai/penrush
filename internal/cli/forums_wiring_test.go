package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/penrush/penrush/internal/forumscan"
	"github.com/penrush/penrush/internal/registry"
)

// TestCheck_ForumsFlag_RunsAdvisoryScan proves --forums invokes the scan (via
// the hermetic seam) and renders it, WITHOUT changing the authoritative gate
// exit code (advisory only).
func TestCheck_ForumsFlag_RunsAdvisoryScan(t *testing.T) {
	home := initHome(t) // gate8 off → pure Gate-1 path
	var out, errb bytes.Buffer
	called := false
	e := &Env{
		Args:   []string{"check", "npm", "left-pad@1.3.0", "--forums"},
		Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
		Resolvers: map[string]registry.Resolver{"npm": stubResolver{eco: "npm", published: fixedNow.AddDate(0, 0, -400)}},
		ForumScan: func(_ context.Context, eco, name string) forumscan.Aggregate {
			called = true
			if eco != "npm" || name != "left-pad" {
				t.Errorf("forum scan got eco=%q name=%q, want npm/left-pad", eco, name)
			}
			return forumscan.Aggregate{
				Verdict:       forumscan.VerdictReview,
				Note:          "1 unchecked",
				SearchedCount: 4,
				Unchecked:     []forumscan.Unchecked{{Forum: "Bluesky", Reason: "unreachable"}},
			}
		},
	}
	if code := Run(e); code != ExitPass {
		t.Fatalf("advisory forum scan must NOT change a PASS exit, got %d\n%s", code, out.String())
	}
	if !called {
		t.Fatal("--forums did not invoke the forum scan")
	}
	got := out.String()
	if !strings.Contains(got, "Community Forum Scan") || !strings.Contains(got, "AGGREGATE: REVIEW") {
		t.Errorf("forum render missing:\n%s", got)
	}
	if !strings.Contains(got, "[penrush] PASS") {
		t.Errorf("gate verdict should still print PASS:\n%s", got)
	}
}

// TestCheck_ForumsFlag_DoesNotRunByDefault: a plain check never touches the
// network-bearing forum scan.
func TestCheck_ForumsFlag_DoesNotRunByDefault(t *testing.T) {
	home := initHome(t)
	var out, errb bytes.Buffer
	e := &Env{
		Args:   []string{"check", "npm", "left-pad@1.3.0"},
		Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
		Resolvers: map[string]registry.Resolver{"npm": stubResolver{eco: "npm", published: fixedNow.AddDate(0, 0, -400)}},
		ForumScan: func(_ context.Context, _, _ string) forumscan.Aggregate {
			t.Fatal("forum scan must NOT run without --forums")
			return forumscan.Aggregate{}
		},
	}
	if code := Run(e); code != ExitPass {
		t.Fatalf("plain check exit = %d", code)
	}
	if strings.Contains(out.String(), "Community Forum Scan") {
		t.Errorf("forum scan output leaked without --forums:\n%s", out.String())
	}
}

// TestCheck_UnknownFlagRejected: any flag other than --forums is a usage error.
func TestCheck_UnknownFlagRejected(t *testing.T) {
	home := initHome(t)
	var out, errb bytes.Buffer
	e := &Env{
		Args:   []string{"check", "npm", "left-pad@1.3.0", "--bogus"},
		Stdout: &out, Stderr: &errb, Home: home, Now: clk(),
	}
	if code := Run(e); code != ExitUsageErr {
		t.Fatalf("unknown flag must be ExitUsageErr, got %d", code)
	}
	if !strings.Contains(errb.String(), "unknown flag") {
		t.Errorf("expected an unknown-flag error, got:\n%s", errb.String())
	}
}
