package registry

import (
	"context"
	"testing"
	"time"
)

// TestEcosystemNames pins each chunk-2 resolver's stable ecosystem key — these
// strings are the override/cache key prefixes and the CLI dispatch keys, so a
// rename is a breaking change that this test catches.
func TestEcosystemNames(t *testing.T) {
	cases := []struct {
		r    Resolver
		want string
	}{
		{&Cargo{}, "cargo"},
		{&RubyGems{}, "gem"},
		{&GoMod{}, "go"},
		{&Docker{}, "docker"},
		{&MCP{}, "mcp"},
	}
	for _, c := range cases {
		if got := c.r.Ecosystem(); got != c.want {
			t.Errorf("Ecosystem() = %q, want %q", got, c.want)
		}
	}
}

// TestSleepCtxZeroDuration: a non-positive duration returns immediately.
func TestSleepCtxZeroDuration(t *testing.T) {
	if err := sleepCtx(context.Background(), 0); err != nil {
		t.Fatalf("zero-duration sleep should return nil, got %v", err)
	}
	if err := sleepCtx(context.Background(), -time.Second); err != nil {
		t.Fatalf("negative-duration sleep should return nil, got %v", err)
	}
}

// TestTokenBucketRefillCaps: tokens never exceed burst no matter how long we
// wait between calls (prevents an idle bucket from banking unlimited burst).
func TestTokenBucketRefillCaps(t *testing.T) {
	var virtual time.Duration
	b := &tokenBucket{
		rate: 1, burst: 1, tokens: 1,
		nowFn:   func() time.Time { return time.Unix(0, 0).Add(virtual) },
		sleepFn: func(_ context.Context, d time.Duration) error { virtual += d; return nil },
	}
	b.last = b.nowFn()
	// Idle for a long virtual stretch, then take two tokens back-to-back. The
	// second must still wait ~1s — the first big refill is capped at burst=1.
	virtual += 100 * time.Second
	if err := b.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	start := virtual
	if err := b.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if virtual-start < 900*time.Millisecond {
		t.Fatalf("burst should be capped at 1; second Wait waited only %v", virtual-start)
	}
}
