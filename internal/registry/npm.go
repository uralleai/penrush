package registry

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// NPM resolves publish times from the npm registry.
//
// SD.2: GET https://registry.npmjs.org/{package} -> `time` map ("an object
// mapping versions to the time published, along with created and modified
// timestamps" — npm/registry package-metadata doc). The abbreviated
// install-metadata format does not carry `time`, so the full document is
// requested and only the needed keys are decoded.
type NPM struct {
	Client  *Client
	BaseURL string // default https://registry.npmjs.org
}

func (n *NPM) Ecosystem() string { return "npm" }

type npmDoc struct {
	Time     map[string]string `json:"time"`
	DistTags map[string]string `json:"dist-tags"`
}

func (n *NPM) Resolve(ctx context.Context, name, version string) (*Resolution, error) {
	base := n.BaseURL
	if base == "" {
		base = "https://registry.npmjs.org"
	}
	// Scoped names URL-encoded (SD.2): @scope/pkg -> @scope%2Fpkg
	u := base + "/" + url.PathEscape(name)
	var doc npmDoc
	if err := n.Client.GetJSON(ctx, u, nil, &doc); err != nil {
		return nil, err
	}
	target := version
	if target == "" {
		target = doc.DistTags["latest"]
		if target == "" {
			return nil, fmt.Errorf("npm: no version given and no latest dist-tag for %s", name)
		}
	}
	ts, ok := doc.Time[target]
	if !ok {
		return nil, fmt.Errorf("%w: npm %s@%s has no publish time entry", ErrNotFound, name, target)
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return nil, fmt.Errorf("npm: unparseable publish time %q for %s@%s", ts, name, target)
	}
	return &Resolution{
		PublishedAt: t,
		SourceURL:   u,
		Confidence:  "version-publish-time",
	}, nil
}
