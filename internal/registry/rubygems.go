package registry

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// RubyGems resolves gem version publish times from rubygems.org.
//
// SD.5: GET https://rubygems.org/api/v1/versions/{gem}.json -> an array of
// version detail objects, each with `number` and `created_at` (primary source:
// guides.rubygems.org/rubygems-org-api; re-verified 2026-06-16, example
// timestamp "2011-08-08T21:23:40.254Z" — note fractional seconds). The
// reference hook's redundant latest.json pre-call is dropped: this one call
// carries every version.
//
// Rate limit: "API and website: 10 requests per second"
// (guides.rubygems.org/rubygems-org-rate-limits). A 10 rps token bucket
// enforces the ceiling.
type RubyGems struct {
	Client  *Client
	BaseURL string // default https://rubygems.org
	bucket  *tokenBucket
}

func (r *RubyGems) Ecosystem() string { return "gem" }

type rubyVersion struct {
	Number     string `json:"number"`
	CreatedAt  string `json:"created_at"`
	Prerelease bool   `json:"prerelease"`
}

func (r *RubyGems) Resolve(ctx context.Context, name, version string) (*Resolution, error) {
	if r.bucket == nil {
		r.bucket = newTokenBucket(10, 10) // 10 rps (RubyGems rate-limit doc)
	}
	if err := r.bucket.Wait(ctx); err != nil {
		return nil, err
	}
	base := r.BaseURL
	if base == "" {
		base = "https://rubygems.org"
	}
	u := base + "/api/v1/versions/" + url.PathEscape(name) + ".json"
	var versions []rubyVersion
	if err := r.Client.GetJSON(ctx, u, nil, &versions); err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("%w: gem %s has no published versions", ErrNotFound, name)
	}

	pick := func(v rubyVersion) (*Resolution, error) {
		t, err := parseRubyTime(v.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("gem: unparseable created_at %q for %s-%s", v.CreatedAt, name, v.Number)
		}
		return &Resolution{PublishedAt: t, SourceURL: u, Confidence: "version-publish-time"}, nil
	}

	if version != "" {
		for _, v := range versions {
			if v.Number == version {
				return pick(v)
			}
		}
		return nil, fmt.Errorf("%w: gem %s-%s has no matching version entry", ErrNotFound, name, version)
	}
	// No version pinned: the API returns versions newest-first, so the first
	// non-prerelease entry is the effective latest; fall back to versions[0].
	for _, v := range versions {
		if !v.Prerelease {
			return pick(v)
		}
	}
	return pick(versions[0])
}

// parseRubyTime accepts both fractional-second (RFC3339Nano, e.g.
// "…40.254Z") and whole-second RFC3339 forms.
func parseRubyTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}
