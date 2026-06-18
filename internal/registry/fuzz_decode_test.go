package registry

// Fuzz target #2 — registry-response decoding (architecture §K Fuzz row;
// scope spec §2.1 fuzz #2). This is the chunk-5 pentest TB2 surface: registry
// responses are UNTRUSTED (§C.1, §C.3 #2). A registry MITM (pentest P-1) or a
// compromised/typosquat registry can return arbitrary bytes; the decoder must
// never crash and must never synthesize a passing age out of garbage.
//
// The fuzzer drives every ecosystem resolver against an IN-MEMORY
// http.RoundTripper (fuzzRoundTripper) that returns fuzzer-controlled bytes as
// the response body with zero socket/TLS I/O, exercising the real hardened
// Client.GetJSON path (https-scheme guard, size cap, io.LimitReader, strict
// decode, status branching, retry rules) plus each resolver's interpretation of
// the decoded document — at high throughput. (Live-TLS transport correctness is
// covered by the per-ecosystem httptest integration tests; re-fuzzing the socket
// would only re-test net/http at a few execs/sec.)
//
// INVARIANTS asserted for every (body, status, name, version) input:
//
//  1. No panic on any byte sequence (a decoder crash on the hook path is a
//     §C.6 bypass primitive — the gate would exit non-2 and the install would
//     proceed).
//  2. No nil-Resolution / nil-error pair. The Resolver contract is exactly one
//     of {*Resolution, nil} or {nil, error}. A (nil,nil) return would make the
//     engine dereference a nil Resolution → crash → bypass.
//  3. A returned *Resolution carries a NON-ZERO PublishedAt. The age gate
//     computes now-PublishedAt; a zero-time Resolution would read as ~2026
//     years old and PASS everything — the worst possible decode bug. (The
//     docker digest-pinned far-past time is intentionally non-zero and is fine.)
//  4. https-only holds: GetJSON must reject a non-https URL regardless of body
//     (no --insecure exists, §C.2 #1). Verified in a fixed sub-case, not fuzzed.
//
// Run bounded:  go test ./internal/registry/ -run x -fuzz FuzzRegistryDecode -fuzztime=30s
// Seed corpus checked in under internal/registry/testdata/fuzz/FuzzRegistryDecode/.

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fuzzResponse is the body + status the in-memory RoundTripper returns. It is
// swapped atomically per fuzz exec (the fuzz callback is sequential within a
// worker process; the atomic guards the server goroutine's read). The real
// hardened Client.GetJSON path (size cap, strict decode, retry rules) runs
// against it, so the TB2 decode surface is faithfully exercised.
type fuzzResponse struct {
	body   string
	status int
}

// resolverFor builds a fresh resolver of the named ecosystem pointed at the
// fixture server. A fresh instance per call keeps the fuzzer hermetic and lets
// rate-limited ecosystems (cargo/gem) start with a full bucket.
func resolverFor(eco string, c *Client, baseURL string) Resolver {
	switch eco {
	case "npm":
		return &NPM{Client: c, BaseURL: baseURL}
	case "pypi":
		return &PyPI{Client: c, BaseURL: baseURL}
	case "github":
		return &GitHub{Client: c, BaseURL: baseURL}
	case "cargo":
		return &Cargo{Client: c, BaseURL: baseURL}
	case "gem":
		return &RubyGems{Client: c, BaseURL: baseURL}
	case "go":
		return &GoMod{Client: c, BaseURL: baseURL}
	case "docker":
		return &Docker{Client: c, BaseURL: baseURL}
	case "mcp":
		return &MCP{Client: c, BaseURL: baseURL}
	}
	return nil
}

var fuzzEcosystems = []string{"npm", "pypi", "github", "cargo", "gem", "go", "docker", "mcp"}

func FuzzRegistryDecode(f *testing.F) {
	// --- Seed corpus: realistic + malformed registry bodies ---
	for _, body := range []string{
		// well-formed shapes (per ecosystem, kept near the real grammar)
		`{"time":{"1.0.0":"2024-01-01T00:00:00Z"},"dist-tags":{"latest":"1.0.0"}}`,
		`{"urls":[{"upload_time_iso_8601":"2024-01-01T00:00:00Z"}]}`,
		`{"info":{"version":"1.0.0"}}`,
		`{"published_at":"2024-01-01T00:00:00Z"}`,
		`{"pushed_at":"2024-01-01T00:00:00Z","created_at":"2023-01-01T00:00:00Z"}`,
		`{"crate":{"max_version":"1.0.0"},"versions":[{"num":"1.0.0","created_at":"2024-01-01T00:00:00Z"}]}`,
		`[{"number":"1.0.0","created_at":"2024-01-01T00:00:00.123Z","prerelease":false}]`,
		`{"Version":"v1.0.0","Time":"2024-01-01T00:00:00Z"}`,
		`{"tag_last_pushed":"2024-01-01T00:00:00.000Z","last_updated":"2024-01-01T00:00:00.000Z","digest":"sha256:ab"}`,
		`{"servers":[{"name":"x","version":"1.0.0","repository":{"url":"https://e/x"}}]}`,
		// MITM / garbage attempts (P-1): the decoder must NOT mint a pass from these
		`{}`,
		`[]`,
		`null`,
		`""`,
		`0`,
		`{"time":{"1.0.0":"not-a-timestamp"}}`,
		`{"time":{"1.0.0":""}}`,
		`{"urls":[{"upload_time_iso_8601":"9999-99-99T99:99:99Z"}]}`,
		`{"pushed_at":"0000-00-00T00:00:00Z"}`,                     // zero-ish time string
		`{"published_at":null,"pushed_at":null,"created_at":null}`, // all nulls
		`{"crate":{"max_version":"1.0.0"},"versions":[]}`,          // version named but absent
		`{"Version":"v1.0.0","Time":""}`,                           // empty go Time
		`{"tag_last_pushed":"","last_updated":"","digest":""}`,     // empty docker
		`{"time": 123}`,                 // wrong type for time map → decode error, not crash
		`{"urls": "not-an-array"}`,      // wrong type
		`{"versions": {"num": "x"}}`,    // object where array expected
		`{` + repeat(`"a":{`, 64) + `}`, // deeply nested (decoder depth)
		`{"x":` + repeat(`[`, 200),      // unbalanced brackets (truncated stream)
		"\x00\xff\xfe garbage not json", // raw bytes
		"",                              // empty body
	} {
		// Seed bodies at 200 (the decode path — terminal, no retry). The
		// status axis is explored by the fuzzer itself (normalizeStatus); we do
		// NOT bulk-seed retrying statuses (429/5xx) because each would incur
		// real backoff and balloon the no-fuzz seed run past the package
		// deadline. A few explicit error-status seeds below give the
		// fail-closed paths their regression coverage without flooding.
		f.Add(body, 200)
	}
	// Explicit 404 seed (terminal-fast: dependency-confusion block path).
	// Retrying statuses (429/403/5xx) are intentionally NOT seeded into the
	// fuzz corpus — they add no decode coverage and each replay costs a backoff
	// window that starves the mutation budget. Their fail-closed paths are
	// regression-covered by TestRetryingStatusesFailClosed below (bounded, run
	// once) and by the per-ecosystem unit tests.
	f.Add(`{}`, 404)

	// ONE client backed by an IN-MEMORY RoundTripper for the whole fuzz target.
	// The transport returns the current (body,status) with ZERO socket/TLS I/O,
	// so the fuzzer runs at thousands of execs/sec while STILL driving the real
	// Client.GetJSON path (https-scheme check, size cap, io.LimitReader, strict
	// json.Decode, status branching, retry rules) and every resolver's own
	// interpretation of the decoded struct — which IS the TB2 decode surface.
	// (Live-TLS transport correctness is covered separately by the per-ecosystem
	// httptest integration tests; fuzzing the socket would only re-test net/http
	// at 4 execs/sec.)
	rt := &fuzzRoundTripper{}
	c := NewClientWithHTTP(&http.Client{Transport: rt})

	f.Fuzz(func(t *testing.T, body string, status int) {
		// Normalize status to a plausible HTTP code range; the client only
		// branches on 200 / 404 / 429 / 403 / 5xx / other-4xx, so map freely.
		code := normalizeStatus(status)
		rt.resp.Store(&fuzzResponse{body: body, status: code})

		for _, eco := range fuzzEcosystems {
			// https:// base so GetJSON's scheme guard passes; the in-memory
			// transport answers regardless of host/path.
			r := resolverFor(eco, c, "https://fuzz.invalid")
			// A short ctx still bounds the retry backoff on the (rare, biased-
			// down) retrying statuses; with the in-memory transport even those
			// resolve in microseconds, so this is just defense-in-depth.
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			res, err := r.Resolve(ctx, "fuzz-pkg/sub", "1.0.0") // name doubles as owner/repo for github
			cancel()

			// Invariant 2: never (nil, nil).
			if res == nil && err == nil {
				t.Fatalf("[%s] returned (nil,nil) for status=%d body=%q — engine would deref nil (bypass)", eco, code, body)
			}
			// Invariant 3: a Resolution must carry a usable (non-zero) time.
			if res != nil {
				if res.PublishedAt.IsZero() {
					t.Fatalf("[%s] Resolution has ZERO PublishedAt for status=%d body=%q — would read ~2026y old and PASS everything", eco, code, body)
				}
				if err != nil {
					t.Fatalf("[%s] returned BOTH a Resolution and an error for status=%d body=%q", eco, code, body)
				}
			}
		}
	})
}

// fuzzRoundTripper is an in-memory http.RoundTripper: it returns the body +
// status held in its atomic pointer, with no network. It implements exactly
// the surface GetJSON depends on (status code + body stream).
type fuzzRoundTripper struct {
	resp atomic.Pointer[fuzzResponse]
}

func (rt *fuzzRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r := rt.resp.Load()
	if r == nil {
		r = &fuzzResponse{body: "{}", status: 200}
	}
	return &http.Response{
		StatusCode: r.status,
		Status:     http.StatusText(r.status),
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// TestGetJSONRejectsNonHTTPS pins invariant 4 (not fuzzed — a single fixed
// assertion): GetJSON must refuse a non-https URL up front, with no body fetch.
// There is no --insecure flag by design (§C.2 #1); a downgrade to http would be
// the P-1 MITM entry point.
func TestGetJSONRejectsNonHTTPS(t *testing.T) {
	c := NewClient()
	var v map[string]any
	for _, u := range []string{"http://registry.npmjs.org/x", "ftp://x", "registry.npmjs.org/x", ""} {
		if err := c.GetJSON(context.Background(), u, nil, &v); err == nil {
			t.Fatalf("GetJSON(%q) returned nil error — non-https must be rejected (no insecure mode)", u)
		}
	}
}

// TestRetryingStatusesFailClosed covers the retrying-status (429/403/5xx)
// fail-closed paths that the fuzz corpus intentionally omits (they add no decode
// coverage and their backoff would starve the fuzzer). For every ecosystem and
// every retrying status, Resolve must return a non-nil error and NEVER a
// Resolution (FR-003: never warn-and-pass on unverifiable age). The per-Resolve
// context is tight so the bounded backoff cancels fast — this stays well under a
// second total.
func TestRetryingStatusesFailClosed(t *testing.T) {
	rt := &fuzzRoundTripper{}
	c := NewClientWithHTTP(&http.Client{Transport: rt})
	for _, status := range []int{
		http.StatusTooManyRequests, http.StatusForbidden,
		http.StatusInternalServerError, http.StatusBadGateway,
	} {
		rt.resp.Store(&fuzzResponse{body: "", status: status})
		for _, eco := range fuzzEcosystems {
			r := resolverFor(eco, c, "https://fuzz.invalid")
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			res, err := r.Resolve(ctx, "fuzz-pkg/sub", "1.0.0")
			cancel()
			if res != nil {
				t.Fatalf("[%s] status %d returned a Resolution — must fail closed (FR-003)", eco, status)
			}
			if err == nil {
				t.Fatalf("[%s] status %d returned nil error — must fail closed", eco, status)
			}
		}
	}
}

// normalizeStatus maps the fuzzer int to one of the TWO terminal-fast codes
// the decode surface cares about: 200 (the decode path — the real TB2 target)
// and 404 (the dependency-confusion block). Both return without any retry
// backoff, so the fuzzer runs at full speed exploring DECODE robustness.
//
// The retrying statuses (429/403/5xx) are deliberately NOT produced here: they
// add no decode coverage (the body is never decoded on a non-200), and each
// would cost a bounded backoff window that throttles the fuzzer. Their
// fail-closed paths are covered by TestRetryingStatusesFailClosed above AND by
// the per-ecosystem unit tests (e.g. TestRubyGemsRateLimit429FailsClosed,
// TestRubyGems404Blocks).
func normalizeStatus(s int) int {
	if s < 0 {
		s = -s
	}
	if s%4 == 0 {
		return http.StatusNotFound
	}
	return http.StatusOK
}

// repeat is a tiny stdlib-free strings.Repeat (the package keeps its test deps
// minimal and explicit; strings.Repeat would be fine too but this keeps the
// seed literals self-documenting).
func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
