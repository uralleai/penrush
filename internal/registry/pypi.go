package registry

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// PyPI resolves upload times from pypi.org.
//
// SD.3: GET https://pypi.org/pypi/{project}/{version}/json ->
// urls[].upload_time_iso_8601 (docs.pypi.org/api/json). The project-level
// `releases` key is deprecated, so the PER-VERSION endpoint is used. When no
// version is specified, one project-level call resolves info.version first.
//
// Conservatism note (deliberate, documented): a version's file set can GROW
// after first publication (new wheels added later). The NEWEST file upload
// time is used — the most recent code in the artifact set is what the
// cooldown is measuring. (The internal reference hook used files[0]; this is
// a deliberate, stricter divergence.)
type PyPI struct {
	Client  *Client
	BaseURL string // default https://pypi.org
}

func (p *PyPI) Ecosystem() string { return "pypi" }

type pypiProjectDoc struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
}

type pypiVersionDoc struct {
	URLs []struct {
		UploadTimeISO8601 string `json:"upload_time_iso_8601"`
	} `json:"urls"`
}

func (p *PyPI) Resolve(ctx context.Context, name, version string) (*Resolution, error) {
	base := p.BaseURL
	if base == "" {
		base = "https://pypi.org"
	}
	if version == "" {
		var proj pypiProjectDoc
		if err := p.Client.GetJSON(ctx, base+"/pypi/"+url.PathEscape(name)+"/json", nil, &proj); err != nil {
			return nil, err
		}
		version = proj.Info.Version
		if version == "" {
			return nil, fmt.Errorf("pypi: cannot determine latest version for %s", name)
		}
	}
	u := base + "/pypi/" + url.PathEscape(name) + "/" + url.PathEscape(version) + "/json"
	var doc pypiVersionDoc
	if err := p.Client.GetJSON(ctx, u, nil, &doc); err != nil {
		return nil, err
	}
	if len(doc.URLs) == 0 {
		return nil, fmt.Errorf("%w: pypi %s==%s has no release files", ErrNotFound, name, version)
	}
	var newest time.Time
	for _, f := range doc.URLs {
		t, err := time.Parse(time.RFC3339, f.UploadTimeISO8601)
		if err != nil {
			return nil, fmt.Errorf("pypi: unparseable upload time %q for %s==%s", f.UploadTimeISO8601, name, version)
		}
		if t.After(newest) {
			newest = t
		}
	}
	return &Resolution{
		PublishedAt: newest,
		SourceURL:   u,
		Confidence:  "version-publish-time",
	}, nil
}
