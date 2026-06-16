package registry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// GitHub resolves repo recency from api.github.com.
//
// SD.7 ordering (preserves the 2026-05-25 internal bug-fix exactly):
//  1. PRIMARY:  GET /repos/{owner}/{repo}/releases/latest -> published_at
//  2. FALLBACK: GET /repos/{owner}/{repo} -> pushed_at
//  3. LAST RESORT: created_at
//
// Token: auto-detect GITHUB_TOKEN / GH_TOKEN env (read-only use, never
// stored) per SL-5 — no token is REQUIRED; Gate 1 stays fail-closed either
// way. The config github_token_env name takes precedence when set.
type GitHub struct {
	Client   *Client
	BaseURL  string // default https://api.github.com
	TokenEnv string // optional config-named env var to read a token from
}

func (g *GitHub) Ecosystem() string { return "github" }

func (g *GitHub) token() string {
	if g.TokenEnv != "" {
		if v := os.Getenv(g.TokenEnv); v != "" {
			return v
		}
	}
	for _, env := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return ""
}

func (g *GitHub) headers() map[string]string {
	h := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if t := g.token(); t != "" {
		h["Authorization"] = "Bearer " + t
	}
	return h
}

type ghRelease struct {
	PublishedAt string `json:"published_at"`
}

type ghRepo struct {
	PushedAt  string `json:"pushed_at"`
	CreatedAt string `json:"created_at"`
}

// Resolve treats name as "owner/repo"; version is ignored (HEAD-recency is
// what the age gate measures for repos).
func (g *GitHub) Resolve(ctx context.Context, name, version string) (*Resolution, error) {
	owner, repo, ok := strings.Cut(name, "/")
	if !ok || owner == "" || repo == "" {
		return nil, fmt.Errorf("github: artifact must be owner/repo, got %q", name)
	}
	repo = strings.TrimSuffix(repo, ".git")
	base := g.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}

	// 1. Latest release published_at
	relURL := fmt.Sprintf("%s/repos/%s/%s/releases/latest", base, owner, repo)
	var rel ghRelease
	err := g.Client.GetJSON(ctx, relURL, g.headers(), &rel)
	if err == nil && rel.PublishedAt != "" {
		if t, perr := time.Parse(time.RFC3339, rel.PublishedAt); perr == nil {
			return &Resolution{PublishedAt: t, SourceURL: relURL, Confidence: "release-published-at"}, nil
		}
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		// Transport/5xx/rate-limit on the primary endpoint: fail closed here
		// rather than masking an outage with the fallback (the fallback is for
		// repos WITHOUT releases, not for a broken API path).
		return nil, err
	}

	// 2. pushed_at, 3. created_at
	repoURL := fmt.Sprintf("%s/repos/%s/%s", base, owner, repo)
	var rd ghRepo
	if err := g.Client.GetJSON(ctx, repoURL, g.headers(), &rd); err != nil {
		return nil, err
	}
	if rd.PushedAt != "" {
		if t, perr := time.Parse(time.RFC3339, rd.PushedAt); perr == nil {
			return &Resolution{PublishedAt: t, SourceURL: repoURL, Confidence: "pushed-at-fallback"}, nil
		}
	}
	if rd.CreatedAt != "" {
		if t, perr := time.Parse(time.RFC3339, rd.CreatedAt); perr == nil {
			return &Resolution{PublishedAt: t, SourceURL: repoURL, Confidence: "created-at-last-resort"}, nil
		}
	}
	return nil, fmt.Errorf("github: no usable timestamp for %s/%s", owner, repo)
}
