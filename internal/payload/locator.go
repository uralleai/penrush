package payload

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// ArtifactRef is a resolved, ready-to-fetch artifact: its download URL and the
// container format the archive reader should use. The URL is derived from
// registry metadata (untrusted) and MUST be run through ValidateFetchURL before
// any fetch.
type ArtifactRef struct {
	Ecosystem string
	Name      string
	Version   string
	URL       string
	Format    Format
}

// MetadataFetch fetches JSON from an https registry URL into v. The scanner
// backs this with the hardened registry client; tests back it with a fixture.
type MetadataFetch func(ctx context.Context, url string, v any) error

// baseURLs are the metadata endpoints per ecosystem; overridable for tests.
type baseURLs struct {
	npm  string // default https://registry.npmjs.org
	pypi string // default https://pypi.org
}

func (b baseURLs) npmBase() string {
	if b.npm != "" {
		return b.npm
	}
	return "https://registry.npmjs.org"
}
func (b baseURLs) pypiBase() string {
	if b.pypi != "" {
		return b.pypi
	}
	return "https://pypi.org"
}

// Locate resolves the artifact-download URL for the given coordinate. npm/pypi
// consult registry metadata (the download URL is authoritative there); crates
// and gem follow a deterministic, well-documented URL scheme. docker is handled
// by the scanner (config blob), not here.
func (b baseURLs) Locate(ctx context.Context, eco, name, version string, mf MetadataFetch) (ArtifactRef, error) {
	switch eco {
	case "npm":
		return b.locateNPM(ctx, name, version, mf)
	case "pypi":
		return b.locatePyPI(ctx, name, version, mf)
	case "cargo":
		return ArtifactRef{Ecosystem: eco, Name: name, Version: version, Format: FormatTarGz,
			URL: fmt.Sprintf("https://static.crates.io/crates/%s/%s-%s.crate", url.PathEscape(name), name, version)}, nil
	case "gem":
		return ArtifactRef{Ecosystem: eco, Name: name, Version: version, Format: FormatGem,
			URL: fmt.Sprintf("https://rubygems.org/downloads/%s-%s.gem", name, version)}, nil
	default:
		return ArtifactRef{}, fmt.Errorf("payload: no artifact locator for ecosystem %q", eco)
	}
}

type npmVersionsDoc struct {
	DistTags map[string]string `json:"dist-tags"`
	Versions map[string]struct {
		Dist struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
	} `json:"versions"`
}

func (b baseURLs) locateNPM(ctx context.Context, name, version string, mf MetadataFetch) (ArtifactRef, error) {
	var doc npmVersionsDoc
	if err := mf(ctx, b.npmBase()+"/"+url.PathEscape(name), &doc); err != nil {
		return ArtifactRef{}, err
	}
	if version == "" {
		version = doc.DistTags["latest"]
		if version == "" {
			return ArtifactRef{}, fmt.Errorf("payload: npm %s has no latest dist-tag", name)
		}
	}
	v, ok := doc.Versions[version]
	if !ok || v.Dist.Tarball == "" {
		return ArtifactRef{}, fmt.Errorf("payload: npm %s@%s has no dist.tarball", name, version)
	}
	return ArtifactRef{Ecosystem: "npm", Name: name, Version: version, URL: v.Dist.Tarball, Format: FormatTarGz}, nil
}

type pypiVersionDoc struct {
	URLs []struct {
		URL         string `json:"url"`
		PackageType string `json:"packagetype"` // "sdist" | "bdist_wheel"
		Filename    string `json:"filename"`
	} `json:"urls"`
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
}

func (b baseURLs) locatePyPI(ctx context.Context, name, version string, mf MetadataFetch) (ArtifactRef, error) {
	if version == "" {
		var proj pypiVersionDoc
		if err := mf(ctx, b.pypiBase()+"/pypi/"+url.PathEscape(name)+"/json", &proj); err != nil {
			return ArtifactRef{}, err
		}
		version = proj.Info.Version
		if version == "" {
			return ArtifactRef{}, fmt.Errorf("payload: pypi %s has no version", name)
		}
	}
	var doc pypiVersionDoc
	if err := mf(ctx, b.pypiBase()+"/pypi/"+url.PathEscape(name)+"/"+url.PathEscape(version)+"/json", &doc); err != nil {
		return ArtifactRef{}, err
	}
	// Prefer an sdist (its setup.py/pyproject.toml is the build-hook surface);
	// fall back to a wheel (a wheel has no setup.py but can carry data files).
	var sdist, wheel *struct{ url, fn string }
	for _, u := range doc.URLs {
		item := struct{ url, fn string }{u.URL, u.Filename}
		if u.PackageType == "sdist" {
			sdist = &item
			break
		}
		if u.PackageType == "bdist_wheel" && wheel == nil {
			wheel = &item
		}
	}
	pick := sdist
	if pick == nil {
		pick = wheel
	}
	if pick == nil {
		return ArtifactRef{}, fmt.Errorf("payload: pypi %s==%s has no downloadable file", name, version)
	}
	return ArtifactRef{Ecosystem: "pypi", Name: name, Version: version, URL: pick.url, Format: pypiFormat(pick.fn)}, nil
}

// pypiFormat maps a filename to its container format.
func pypiFormat(filename string) Format {
	f := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(f, ".tar.gz") || strings.HasSuffix(f, ".tgz"):
		return FormatTarGz
	case strings.HasSuffix(f, ".tar.bz2"):
		return FormatTarBz2
	case strings.HasSuffix(f, ".whl") || strings.HasSuffix(f, ".zip"):
		return FormatZip
	default:
		return FormatUnknown
	}
}
