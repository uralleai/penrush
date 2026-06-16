package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newFixtureClient wraps an httptest TLS server's client so the hardened
// client's https-only + decode + retry rules all execute against the fixture.
func newFixtureClient(srv *httptest.Server) *Client {
	return NewClientWithHTTP(srv.Client())
}

const cargoSerdeFixture = `{
  "crate": {"max_version": "1.0.219", "newest_version": "1.0.219"},
  "versions": [
    {"num": "1.0.219", "created_at": "2026-03-01T10:00:00Z", "yanked": false},
    {"num": "1.0.200", "created_at": "2024-01-01T10:00:00Z", "yanked": false}
  ]
}`

func TestCargoResolveLatest(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/crates/serde" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if ua := r.Header.Get("User-Agent"); ua == "" {
			t.Error("crates.io requires an identifying User-Agent; none sent")
		}
		w.Write([]byte(cargoSerdeFixture))
	}))
	defer srv.Close()

	c := &Cargo{Client: newFixtureClient(srv), BaseURL: srv.URL}
	res, err := c.Resolve(context.Background(), "serde", "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	if !res.PublishedAt.Equal(want) {
		t.Errorf("PublishedAt = %v, want %v", res.PublishedAt, want)
	}
	if res.Confidence != "version-publish-time" {
		t.Errorf("Confidence = %q", res.Confidence)
	}
}

func TestCargoResolvePinnedVersion(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(cargoSerdeFixture))
	}))
	defer srv.Close()
	c := &Cargo{Client: newFixtureClient(srv), BaseURL: srv.URL}
	res, err := c.Resolve(context.Background(), "serde", "1.0.200")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	if !res.PublishedAt.Equal(want) {
		t.Errorf("PublishedAt = %v, want %v", res.PublishedAt, want)
	}
}

func TestCargoVersionNotFound(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(cargoSerdeFixture))
	}))
	defer srv.Close()
	c := &Cargo{Client: newFixtureClient(srv), BaseURL: srv.URL}
	_, err := c.Resolve(context.Background(), "serde", "9.9.9")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound for missing version, got %v", err)
	}
}

func TestCargo404Blocks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := &Cargo{Client: newFixtureClient(srv), BaseURL: srv.URL}
	_, err := c.Resolve(context.Background(), "ghost-crate", "1.0.0")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 must map to ErrNotFound (fail-closed red flag), got %v", err)
	}
}

func TestCargo5xxFailsClosed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c := &Cargo{Client: newFixtureClient(srv), BaseURL: srv.URL}
	_, err := c.Resolve(context.Background(), "serde", "1.0.0")
	if err == nil {
		t.Fatal("5xx must fail closed (return an error), got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatal("5xx is a transport error, not ErrNotFound")
	}
}

// TestCargoTokenBucketTiming verifies the 1 rps governor actually delays the
// second request by ~1s, using injected clock + sleep so the test is fast and
// deterministic (no real wall-clock sleeping).
func TestCargoTokenBucketTiming(t *testing.T) {
	var virtual time.Duration
	b := &tokenBucket{
		rate:   1, // 1 rps
		burst:  1,
		tokens: 1,
		nowFn:  func() time.Time { return time.Unix(0, 0).Add(virtual) },
		sleepFn: func(_ context.Context, d time.Duration) error {
			virtual += d // advance virtual clock instead of real sleeping
			return nil
		},
	}
	b.last = b.nowFn()

	// First Wait consumes the single burst token immediately (no sleep).
	if err := b.Wait(context.Background()); err != nil {
		t.Fatalf("first Wait: %v", err)
	}
	if virtual != 0 {
		t.Fatalf("first Wait should not sleep, virtual=%v", virtual)
	}
	// Second Wait must block ~1s (deficit / rate = 1/1 = 1s).
	if err := b.Wait(context.Background()); err != nil {
		t.Fatalf("second Wait: %v", err)
	}
	if virtual < 900*time.Millisecond || virtual > 1100*time.Millisecond {
		t.Fatalf("1 rps bucket should delay ~1s, got %v", virtual)
	}
}

func TestTokenBucketRespectsContextCancel(t *testing.T) {
	b := newTokenBucket(0.001, 1) // ~1 token / 1000s: second Wait blocks a long time
	if err := b.Wait(context.Background()); err != nil {
		t.Fatalf("first Wait: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	if err := b.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait must honor a cancelled context, got %v", err)
	}
}
