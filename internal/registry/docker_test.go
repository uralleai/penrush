package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Mirrors the live-verified Docker Hub tags shape (2026-06-16).
const alpineTagFixture = `{
  "last_updated": "2026-06-16T02:24:50.303297Z",
  "tag_last_pushed": "2026-06-16T02:24:50.303297Z",
  "digest": "sha256:f5064d3e5f88c467c714509f491853ab2d951932c5cad699c0cb969dcec6f3b4"
}`

func TestDockerHubTagResolvesTimestamp(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bare official image normalizes to the library/ namespace.
		if r.URL.Path != "/v2/repositories/library/alpine/tags/latest" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(alpineTagFixture))
	}))
	defer srv.Close()
	d := &Docker{Client: newFixtureClient(srv), BaseURL: srv.URL}
	res, err := d.Resolve(context.Background(), "alpine", "latest")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := time.Date(2026, 6, 16, 2, 24, 50, 303297000, time.UTC)
	if !res.PublishedAt.Equal(want) {
		t.Errorf("PublishedAt = %v, want %v", res.PublishedAt, want)
	}
	if res.Confidence != "tag-last-pushed" {
		t.Errorf("Confidence = %q", res.Confidence)
	}
}

func TestDockerDigestPinPassesAnyRegistry(t *testing.T) {
	// Server must NOT be contacted for a digest-pinned reference.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("digest-pinned reference must not hit the registry")
	}))
	defer srv.Close()
	d := &Docker{Client: newFixtureClient(srv), BaseURL: srv.URL}

	for _, ref := range []string{
		"alpine",
		"ghcr.io/owner/img",
		"quay.io/team/svc",
	} {
		res, err := d.Resolve(context.Background(), ref, "sha256:f5064d3e5f88c467c714509f491853ab2d951932c5cad699c0cb969dcec6f3b4")
		if err != nil {
			t.Fatalf("digest pin for %q: %v", ref, err)
		}
		if res.Confidence != "digest-pinned" {
			t.Errorf("%q: Confidence = %q, want digest-pinned", ref, res.Confidence)
		}
		// distantPast guarantees the age gate always clears for a digest pin.
		if !res.PublishedAt.Equal(distantPast) {
			t.Errorf("%q: digest pin PublishedAt = %v, want distantPast", ref, res.PublishedAt)
		}
	}
}

func TestDockerNonHubTagOnlyBlocksWithDigestHint(t *testing.T) {
	d := &Docker{Client: nil, BaseURL: "https://unused.example"}
	for _, ref := range []string{"ghcr.io/owner/img", "quay.io/team/svc:1.2.3"} {
		name, version := splitForTest(ref)
		_, err := d.Resolve(context.Background(), name, version)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("%q: non-Hub tag-only must block (ErrNotFound), got %v", ref, err)
		}
		if !strings.Contains(err.Error(), "sha256") {
			t.Errorf("%q: block message must carry the digest-pinning hint, got %q", ref, err.Error())
		}
	}
}

func TestDockerHub404Blocks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := &Docker{Client: newFixtureClient(srv), BaseURL: srv.URL}
	_, err := d.Resolve(context.Background(), "nonexistent-image-xyz", "latest")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Hub 404 must be ErrNotFound, got %v", err)
	}
}

func TestDockerMalformedDigest(t *testing.T) {
	d := &Docker{Client: nil}
	_, err := d.Resolve(context.Background(), "alpine", "sha256:")
	if err == nil || !strings.Contains(err.Error(), "malformed digest") {
		t.Fatalf("empty digest hex must be rejected, got %v", err)
	}
}

func TestParseDockerRef(t *testing.T) {
	type want struct{ image, tag, digest string }
	cases := map[string]want{
		"alpine":                         {"alpine", "latest", ""},
		"nginx:1.25":                     {"nginx", "1.25", ""},
		"library/alpine:3.19":            {"library/alpine", "3.19", ""},
		"ghcr.io/owner/img:tag":          {"ghcr.io/owner/img", "tag", ""},
		"localhost:5000/img:tag":         {"localhost:5000/img", "tag", ""},
		"alpine@sha256:abc123":           {"alpine", "", "sha256:abc123"},
		"nginx:1.25@sha256:def456":       {"nginx", "", "sha256:def456"},
		"ghcr.io/o/i:t@sha256:aaa111bbb": {"ghcr.io/o/i", "", "sha256:aaa111bbb"},
	}
	for ref, w := range cases {
		img, tag, dig, err := parseDockerRef(ref)
		if err != nil {
			t.Errorf("parseDockerRef(%q) error: %v", ref, err)
			continue
		}
		if img != w.image || tag != w.tag || dig != w.digest {
			t.Errorf("parseDockerRef(%q) = (%q,%q,%q), want (%q,%q,%q)",
				ref, img, tag, dig, w.image, w.tag, w.digest)
		}
	}
}

func TestSplitRegistryHost(t *testing.T) {
	cases := []struct{ in, host, repo string }{
		{"alpine", "", "alpine"},
		{"library/alpine", "", "library/alpine"},
		{"ghcr.io/owner/img", "ghcr.io", "owner/img"},
		{"quay.io/team/svc", "quay.io", "team/svc"},
		{"localhost:5000/img", "localhost:5000", "img"},
	}
	for _, c := range cases {
		h, r := splitRegistryHost(c.in)
		if h != c.host || r != c.repo {
			t.Errorf("splitRegistryHost(%q) = (%q,%q), want (%q,%q)", c.in, h, r, c.host, c.repo)
		}
	}
}

// splitForTest mimics the CLI's name@version split for docker refs in tests.
func splitForTest(ref string) (name, version string) {
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}
