package payload

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"
)

// interestingFor returns the allowlist predicate for eco: which archive-entry
// paths are read into memory (§V4.4 — only the small hook allowlist, never the
// whole tree). It MUST stay in sync with internal/installscan.Locate, which
// consumes the same paths. Matching is on the cleaned entry path.
func interestingFor(eco string) func(string) bool {
	base := func(p string) string {
		if i := strings.LastIndex(p, "/"); i >= 0 {
			return p[i+1:]
		}
		return p
	}
	switch eco {
	case "npm":
		return func(p string) bool { return base(p) == "package.json" }
	case "pypi":
		return func(p string) bool {
			b := base(p)
			return b == "setup.py" || b == "pyproject.toml" ||
				(strings.HasSuffix(b, ".py") && (strings.Contains(p, "build") || strings.Contains(p, "hook")))
		}
	case "cargo":
		return func(p string) bool { return base(p) == "build.rs" }
	case "gem":
		return func(p string) bool {
			b := base(p)
			if b == "extconf.rb" {
				return true
			}
			return (strings.HasPrefix(p, "ext/") || strings.Contains(p, "/ext/")) &&
				(strings.HasSuffix(b, ".rb") || strings.HasSuffix(b, ".c"))
		}
	default:
		return func(string) bool { return false }
	}
}

// ErrDockerLiveFetchDeferred is returned when a live docker image-config fetch
// is requested. Docker's RUN-history detection (internal/installscan.Locate
// "docker") is fully implemented and tested against a provided image-config
// blob; the LIVE OCI manifest→config-blob resolution (a distinct registry-auth
// surface) is deferred to the PH-2b-gated follow-up. It is fail-closed: the
// caller BLOCKS with this reason, never silently passes.
var ErrDockerLiveFetchDeferred = errors.New("payload: live docker image-config fetch is deferred (detection implemented; OCI config-blob live fetch pending PH-2b) — fail-closed")

// DefaultBudget is the dedicated Gate-8 wall-clock budget (§V4.7): payload fetch
// is heavier than a metadata call, so it gets its own ceiling; on timeout the
// caller fails closed.
const DefaultBudget = 20 * time.Second

// Scanner performs the end-to-end Gate-8 payload scan: locate → SSRF-validate →
// hardened fetch → bounded in-memory archive read → allowlisted hook contents.
// It NEVER writes to disk and NEVER executes anything.
type Scanner struct {
	Bases   baseURLs
	Meta    MetadataFetch
	Fetcher *Fetcher
	Limits  Limits
	Budget  time.Duration
}

// NewScanner builds a production scanner. meta is the registry-backed JSON
// fetcher (hardened client); tests supply a fixture meta + NewFetcherWithHTTP.
func NewScanner(meta MetadataFetch) *Scanner {
	return &Scanner{
		Meta:    meta,
		Fetcher: NewFetcher(),
		Limits:  DefaultLimits(),
		Budget:  DefaultBudget,
	}
}

// Scan resolves and reads the artifact, returning the allowlisted hook-file
// contents (path -> bytes) for internal/installscan to analyze. Every failure
// path returns an error (the caller fails closed). It applies the dedicated
// Gate-8 wall-clock budget.
func (s *Scanner) Scan(ctx context.Context, eco, name, version string) (map[string][]byte, error) {
	if eco == "docker" {
		return nil, ErrDockerLiveFetchDeferred
	}
	budget := s.Budget
	if budget <= 0 {
		budget = DefaultBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	ref, err := s.Bases.Locate(ctx, eco, name, version, s.Meta)
	if err != nil {
		return nil, err
	}
	if ref.Format == FormatUnknown {
		return nil, ErrUnknownFormat
	}
	// STATIC SSRF check (§V4.6) before any fetch.
	if err := ValidateFetchURL(eco, ref.URL); err != nil {
		return nil, err
	}
	data, err := s.Fetcher.Fetch(ctx, ref.URL)
	if err != nil {
		return nil, err
	}
	return ReadArchive(bytes.NewReader(data), ref.Format, s.Limits, interestingFor(eco))
}
