//go:build forumscan_live

// Live-network smoke test for the forum scanner. It is gated behind the
// `forumscan_live` build tag so `go test ./...` (and therefore CI) NEVER depends
// on external forums. Run explicitly:
//
//	go test -tags forumscan_live -run TestLive ./internal/forumscan/
//
// Optionally set FORUMSCAN_TARGET (default "left-pad") and GITHUB_TOKEN.
package forumscan

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveScanDoesNotPanicAndReturnsValidVerdict(t *testing.T) {
	target := os.Getenv("FORUMSCAN_TARGET")
	if target == "" {
		target = "left-pad"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	agg := Scan(ctx, target, "npm", ResolveGitHubToken(""))

	switch agg.Verdict {
	case VerdictClean, VerdictReview, VerdictFlag:
		// ok — any of the three is a valid live outcome.
	default:
		t.Fatalf("invalid live verdict %q", agg.Verdict)
	}
	if len(agg.Forums) != 5 {
		t.Fatalf("expected 5 forum results, got %d", len(agg.Forums))
	}
	// The fail-closed floor must hold live too: CLEAN requires full coverage.
	if agg.Verdict == VerdictClean && len(agg.Unchecked) != 0 {
		t.Fatalf("CLEAN with %d unchecked forum(s) — fail-closed floor violated live", len(agg.Unchecked))
	}
	t.Logf("live verdict=%s searched=%d unchecked=%d note=%s",
		agg.Verdict, agg.SearchedCount, len(agg.Unchecked), agg.Note)
}
