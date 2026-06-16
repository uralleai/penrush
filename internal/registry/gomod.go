package registry

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// GoMod resolves module-version publish times from the Go module proxy.
//
// SD.6: GET https://proxy.golang.org/{module}/@v/{version}.info ->
// {"Version":"…","Time":"…"} (live-verified 2026-06-16: testify v1.9.0 ->
// "Time":"2024-02-29T14:36:18Z"). proxy.golang.org freshness note: a newly
// published version may take up to 30 minutes to appear — immaterial under a
// 14-day gate.
//
// Module-path case escaping (GOPROXY protocol): an uppercase letter is encoded
// as '!' + its lowercase form (e.g. github.com/Azure -> github.com/!azure), so
// case-insensitive filesystems cannot collide. `@latest` stays forbidden at the
// parser layer (lock-file rule); it is rejected here too as defense in depth —
// the proxy's @latest endpoint is never needed.
type GoMod struct {
	Client  *Client
	BaseURL string // default https://proxy.golang.org
}

func (g *GoMod) Ecosystem() string { return "go" }

type goInfo struct {
	Version string `json:"Version"`
	Time    string `json:"Time"`
}

func (g *GoMod) Resolve(ctx context.Context, name, version string) (*Resolution, error) {
	if version == "" {
		return nil, fmt.Errorf("go: an exact version is required (lock-file rule forbids @latest); got module %q with no version", name)
	}
	if strings.EqualFold(version, "latest") {
		return nil, fmt.Errorf("go: @latest is forbidden (lock-file rule) — pin an exact version of %q", name)
	}
	base := g.BaseURL
	if base == "" {
		base = "https://proxy.golang.org"
	}
	u := base + "/" + escapeModulePath(name) + "/@v/" + escapeModulePath(version) + ".info"
	var info goInfo
	if err := g.Client.GetJSON(ctx, u, nil, &info); err != nil {
		return nil, err
	}
	if info.Time == "" {
		return nil, fmt.Errorf("%w: go %s@%s has no Time in proxy .info", ErrNotFound, name, version)
	}
	t, err := time.Parse(time.RFC3339, info.Time)
	if err != nil {
		return nil, fmt.Errorf("go: unparseable Time %q for %s@%s", info.Time, name, version)
	}
	return &Resolution{
		PublishedAt: t,
		SourceURL:   u,
		Confidence:  "version-publish-time",
	}, nil
}

// escapeModulePath applies the GOPROXY '!'-encoding: every uppercase ASCII
// letter becomes "!"+lowercase. Other characters pass through unchanged (paths
// are already URL-safe in practice; the proxy expects this exact escaping).
func escapeModulePath(s string) string {
	if !hasUpper(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hasUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}
