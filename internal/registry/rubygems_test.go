package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// RubyGems returns versions newest-first; note the fractional-second timestamp
// form documented at guides.rubygems.org/rubygems-org-api.
const railsVersionsFixture = `[
  {"number": "7.1.0",       "created_at": "2026-04-01T21:23:40.254Z", "prerelease": false},
  {"number": "7.1.0.rc1",   "created_at": "2026-03-15T10:00:00.000Z", "prerelease": true},
  {"number": "7.0.0",       "created_at": "2024-01-01T00:00:00.000Z", "prerelease": false}
]`

func TestRubyGemsResolveLatestSkipsPrerelease(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/versions/rails.json" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Write([]byte(railsVersionsFixture))
	}))
	defer srv.Close()
	g := &RubyGems{Client: newFixtureClient(srv), BaseURL: srv.URL}
	res, err := g.Resolve(context.Background(), "rails", "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Newest non-prerelease is 7.1.0 with fractional seconds.
	want := time.Date(2026, 4, 1, 21, 23, 40, 254000000, time.UTC)
	if !res.PublishedAt.Equal(want) {
		t.Errorf("PublishedAt = %v, want %v (fractional-second parse)", res.PublishedAt, want)
	}
}

func TestRubyGemsResolvePinned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(railsVersionsFixture))
	}))
	defer srv.Close()
	g := &RubyGems{Client: newFixtureClient(srv), BaseURL: srv.URL}
	res, err := g.Resolve(context.Background(), "rails", "7.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if !res.PublishedAt.Equal(want) {
		t.Errorf("PublishedAt = %v, want %v", res.PublishedAt, want)
	}
}

func TestRubyGemsEmptyArrayBlocks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	g := &RubyGems{Client: newFixtureClient(srv), BaseURL: srv.URL}
	_, err := g.Resolve(context.Background(), "rails", "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty versions array must be ErrNotFound, got %v", err)
	}
}

func TestRubyGems404Blocks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	g := &RubyGems{Client: newFixtureClient(srv), BaseURL: srv.URL}
	_, err := g.Resolve(context.Background(), "no-such-gem", "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 must be ErrNotFound, got %v", err)
	}
}

func TestRubyGemsRateLimit429FailsClosed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	g := &RubyGems{Client: newFixtureClient(srv), BaseURL: srv.URL}
	_, err := g.Resolve(context.Background(), "rails", "")
	if err == nil {
		t.Fatal("429 must fail closed after retries, got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatal("429 is rate-limit, not ErrNotFound")
	}
}

func TestParseRubyTimeBothForms(t *testing.T) {
	frac, err := parseRubyTime("2011-08-08T21:23:40.254Z")
	if err != nil {
		t.Fatalf("fractional: %v", err)
	}
	if frac.Nanosecond() != 254000000 {
		t.Errorf("fractional nanos = %d, want 254000000", frac.Nanosecond())
	}
	whole, err := parseRubyTime("2024-02-29T14:36:18Z")
	if err != nil {
		t.Fatalf("whole-second: %v", err)
	}
	if whole.Second() != 18 {
		t.Errorf("whole second = %d, want 18", whole.Second())
	}
}
