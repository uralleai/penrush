package registry

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// Cargo resolves crate publish times from crates.io.
//
// SD.4: GET https://crates.io/api/v1/crates/{name} -> versions[].created_at
// (primary source: Rust RFC 3463 — crates.io policy update,
// rust-lang.github.io/rfcs/3463-crates-io-policy-update.html; re-verified
// 2026-06-16). The sparse index carries no publish dates, so the API — not the
// index — is the correct source for Gate 1.
//
// Policy compliance (binding, RFC 3463): "We require users of the crates.io
// API to limit themselves to a maximum of 1 request per second" and require an
// identifying User-Agent (the shared client already sends one). A 1 rps token
// bucket specific to this ecosystem enforces the ceiling even under concurrent
// gate checks.
type Cargo struct {
	Client  *Client
	BaseURL string // default https://crates.io
	bucket  *tokenBucket
}

func (c *Cargo) Ecosystem() string { return "cargo" }

// crates.io ships the publish list newest-LAST under `versions`; each entry
// carries its own `created_at` and the version `num`. The top-level
// `crate.max_version`/`newest_version` selects the default when no version is
// pinned.
type cargoDoc struct {
	Crate struct {
		MaxVersion    string `json:"max_version"`
		NewestVersion string `json:"newest_version"`
	} `json:"crate"`
	Versions []struct {
		Num       string `json:"num"`
		CreatedAt string `json:"created_at"`
		Yanked    bool   `json:"yanked"`
	} `json:"versions"`
}

func (c *Cargo) Resolve(ctx context.Context, name, version string) (*Resolution, error) {
	if c.bucket == nil {
		c.bucket = newTokenBucket(1, 1) // 1 rps, burst 1 (RFC 3463)
	}
	if err := c.bucket.Wait(ctx); err != nil {
		return nil, err
	}
	base := c.BaseURL
	if base == "" {
		base = "https://crates.io"
	}
	u := base + "/api/v1/crates/" + url.PathEscape(name)
	var doc cargoDoc
	if err := c.Client.GetJSON(ctx, u, nil, &doc); err != nil {
		return nil, err
	}
	target := version
	if target == "" {
		target = doc.Crate.MaxVersion
		if target == "" {
			target = doc.Crate.NewestVersion
		}
		if target == "" {
			return nil, fmt.Errorf("cargo: no version given and no max_version for %s", name)
		}
	}
	for _, v := range doc.Versions {
		if v.Num != target {
			continue
		}
		t, err := time.Parse(time.RFC3339, v.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("cargo: unparseable created_at %q for %s@%s", v.CreatedAt, name, target)
		}
		return &Resolution{
			PublishedAt: t,
			SourceURL:   u,
			Confidence:  "version-publish-time",
		}, nil
	}
	return nil, fmt.Errorf("%w: cargo %s@%s has no matching version entry", ErrNotFound, name, target)
}
