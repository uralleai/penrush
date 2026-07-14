// Package registry implements the per-ecosystem registry clients.
//
// Architecture ref: SD.1 common client design:
//   - TLS-only (system roots); there is NO insecure flag, by design (SC.2 #1)
//   - connect timeout 5s, total budget 10s per gate check
//   - max 2 retries with exponential backoff + jitter; NO retry on 4xx
//   - identifying User-Agent
//   - responses size-capped and strictly decoded before use (TB2)
//   - cross-host redirects to non-HTTPS rejected
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"time"
)

// Version is stamped into the User-Agent by the cli package at build time.
var Version = "0.2.0-dev"

// PlaceholderSubdomain: distribution site label on penbag.store is TBD per
// Uri 2026-06-11 — exactly one constant to change when it lands.
const PlaceholderSubdomain = "PLACEHOLDER-SUBDOMAIN"

// UserAgent identifies the client per crates.io policy and good citizenship.
func UserAgent() string {
	return fmt.Sprintf("penrush/%s (+https://%s.penbag.store)", Version, PlaceholderSubdomain)
}

// Resolution is the shared result shape (SA.6): resolve(ecosystem, name,
// version) -> {published_at, source, confidence}.
type Resolution struct {
	PublishedAt time.Time
	SourceURL   string
	Confidence  string // "release-published-at" | "version-publish-time" | "pushed-at-fallback" | "created-at-last-resort"
}

// Resolver is the per-ecosystem interface. Adding an ecosystem is one module
// + one parser rule + fixtures; no engine change.
type Resolver interface {
	Ecosystem() string
	Resolve(ctx context.Context, name, version string) (*Resolution, error)
}

// ErrNotFound distinguishes a 404 (its own red flag — dependency-confusion
// posture, SD.10) from transport errors. Both fail closed; messages differ.
var ErrNotFound = errors.New("artifact not found in registry")

const (
	connectTimeout = 5 * time.Second
	totalBudget    = 10 * time.Second
	maxRetries     = 2
	// maxBody caps response decoding (TB2). npm full-metadata docs for big
	// packages are large; 64 MiB is a hard upper bound, not an expectation.
	maxBody = 64 << 20
)

// Client wraps http.Client with the SD.1 shared behavior.
type Client struct {
	hc *http.Client
}

// NewClientWithHTTP wraps a caller-supplied http.Client (test fixtures use
// httptest.NewTLSServer's client). All decode/retry/https rules still apply.
func NewClientWithHTTP(hc *http.Client) *Client { return &Client{hc: hc} }

// NewClient builds the hardened shared HTTP client.
func NewClient() *Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: connectTimeout,
		}).DialContext,
		TLSHandshakeTimeout:   connectTimeout,
		ResponseHeaderTimeout: connectTimeout,
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
	}
	return &Client{hc: &http.Client{
		Transport: transport,
		Timeout:   totalBudget,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return errors.New("redirect to non-HTTPS rejected")
			}
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}}
}

// GetJSON fetches url (must be https) and decodes into v with a size cap and
// strict field checking disabled (registries add fields; unknown fields are
// ignored, but types are enforced). Retries per SD.1.
func (c *Client) GetJSON(ctx context.Context, url string, headers map[string]string, v any) error {
	if len(url) < 8 || url[:8] != "https://" {
		return errors.New("registry URLs must be https (no insecure mode exists)")
	}
	var lastErr error
	var terminal bool
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<attempt) * 250 * time.Millisecond
			jitter := time.Duration(rand.Int63n(int64(backoff) / 2))
			select {
			case <-time.After(backoff + jitter):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", UserAgent())
		req.Header.Set("Accept", "application/json")
		for k, val := range headers {
			req.Header.Set(k, val)
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			lastErr = err
			continue // network error: retry
		}
		func() {
			defer resp.Body.Close()
			switch {
			case resp.StatusCode == http.StatusOK:
				dec := json.NewDecoder(io.LimitReader(resp.Body, maxBody))
				if derr := dec.Decode(v); derr != nil {
					lastErr = fmt.Errorf("decoding %s: %w", url, derr)
					return
				}
				lastErr = nil
			case resp.StatusCode == http.StatusNotFound:
				lastErr, terminal = fmt.Errorf("%w: %s", ErrNotFound, url), true
			case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden:
				// Rate-limited: retry with backoff up to budget, then the
				// caller fails closed (SD.10). 403 is included because GitHub
				// signals rate limits with it.
				lastErr = fmt.Errorf("rate-limited (%d) at %s", resp.StatusCode, url)
			case resp.StatusCode >= 500:
				lastErr = fmt.Errorf("server error %d at %s", resp.StatusCode, url)
			default:
				// Other 4xx: no retry per SD.1.
				lastErr, terminal = fmt.Errorf("unexpected status %d at %s", resp.StatusCode, url), true
			}
		}()
		if lastErr == nil {
			return nil
		}
		if terminal {
			return lastErr
		}
	}
	return lastErr
}
