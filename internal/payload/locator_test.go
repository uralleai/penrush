package payload

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func fixtureMeta(responses map[string]string) MetadataFetch {
	return func(_ context.Context, url string, v any) error {
		for suffix, body := range responses {
			if strings.HasSuffix(url, suffix) {
				return json.Unmarshal([]byte(body), v)
			}
		}
		return context.DeadlineExceeded // unmatched → error (fail-closed)
	}
}

func TestLocate_CargoDeterministicURL(t *testing.T) {
	ref, err := baseURLs{}.Locate(context.Background(), "cargo", "serde", "1.0.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ref.URL != "https://static.crates.io/crates/serde/serde-1.0.0.crate" || ref.Format != FormatTarGz {
		t.Fatalf("cargo ref wrong: %+v", ref)
	}
	if err := ValidateFetchURL("cargo", ref.URL); err != nil {
		t.Errorf("cargo URL must pass SSRF allowlist: %v", err)
	}
}

func TestLocate_GemDeterministicURL(t *testing.T) {
	ref, err := baseURLs{}.Locate(context.Background(), "gem", "rails", "7.0.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ref.URL != "https://rubygems.org/downloads/rails-7.0.0.gem" || ref.Format != FormatGem {
		t.Fatalf("gem ref wrong: %+v", ref)
	}
	if err := ValidateFetchURL("gem", ref.URL); err != nil {
		t.Errorf("gem URL must pass SSRF allowlist: %v", err)
	}
}

func TestLocate_NPMLatestTag(t *testing.T) {
	meta := fixtureMeta(map[string]string{
		"/left-pad": `{"dist-tags":{"latest":"1.3.0"},"versions":{"1.3.0":{"dist":{"tarball":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}}`,
	})
	ref, err := baseURLs{}.Locate(context.Background(), "npm", "left-pad", "", meta) // empty version → latest
	if err != nil {
		t.Fatal(err)
	}
	if ref.Version != "1.3.0" || !strings.HasSuffix(ref.URL, "left-pad-1.3.0.tgz") {
		t.Fatalf("npm latest resolution wrong: %+v", ref)
	}
}

func TestLocate_NPMMissingTarball(t *testing.T) {
	meta := fixtureMeta(map[string]string{
		"/x": `{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"dist":{}}}}`,
	})
	_, err := baseURLs{}.Locate(context.Background(), "npm", "x", "1.0.0", meta)
	if err == nil {
		t.Fatal("missing dist.tarball must error (fail-closed)")
	}
}

func TestLocate_PyPISdistPreferred(t *testing.T) {
	meta := fixtureMeta(map[string]string{
		"/pypi/req/2.0/json": `{"urls":[{"url":"https://files.pythonhosted.org/req-2.0-py3.whl","packagetype":"bdist_wheel","filename":"req-2.0-py3.whl"},{"url":"https://files.pythonhosted.org/req-2.0.tar.gz","packagetype":"sdist","filename":"req-2.0.tar.gz"}]}`,
	})
	ref, err := baseURLs{}.Locate(context.Background(), "pypi", "req", "2.0", meta)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(ref.URL, ".tar.gz") || ref.Format != FormatTarGz {
		t.Fatalf("pypi should prefer sdist .tar.gz, got %+v", ref)
	}
}

func TestLocate_PyPILatestThenWheel(t *testing.T) {
	meta := fixtureMeta(map[string]string{
		"/pypi/w/json":     `{"info":{"version":"9.9"}}`,
		"/pypi/w/9.9/json": `{"urls":[{"url":"https://files.pythonhosted.org/w-9.9-py3.whl","packagetype":"bdist_wheel","filename":"w-9.9-py3.whl"}]}`,
	})
	ref, err := baseURLs{}.Locate(context.Background(), "pypi", "w", "", meta)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Version != "9.9" || ref.Format != FormatZip {
		t.Fatalf("pypi wheel fallback wrong: %+v", ref)
	}
}

func TestLocate_UnknownEcosystem(t *testing.T) {
	if _, err := (baseURLs{}).Locate(context.Background(), "conda", "x", "1", nil); err == nil {
		t.Fatal("unknown ecosystem must error")
	}
}

func TestPyPIFormat(t *testing.T) {
	cases := map[string]Format{
		"x-1.0.tar.gz": FormatTarGz, "x-1.0.tgz": FormatTarGz,
		"x-1.0.tar.bz2": FormatTarBz2, "x-1.0.whl": FormatZip,
		"x-1.0.zip": FormatZip, "x-1.0.rpm": FormatUnknown,
	}
	for fn, want := range cases {
		if got := pypiFormat(fn); got != want {
			t.Errorf("pypiFormat(%q)=%v want %v", fn, got, want)
		}
	}
}

func TestFormatString(t *testing.T) {
	cases := map[Format]string{
		FormatTarGz: "tar.gz", FormatTarBz2: "tar.bz2", FormatZip: "zip",
		FormatGem: "gem", FormatTar: "tar", FormatDockerConfig: "docker-config", FormatUnknown: "unknown",
	}
	for f, want := range cases {
		if f.String() != want {
			t.Errorf("Format(%d).String()=%q want %q", f, f.String(), want)
		}
	}
}

func TestConstructors_NonNil(t *testing.T) {
	if NewFetcher() == nil || NewScanner(nil) == nil {
		t.Fatal("constructors must return non-nil")
	}
	if NewScanner(nil).Budget != DefaultBudget {
		t.Error("NewScanner should default the budget")
	}
}

func TestPyPIBaseDefaults(t *testing.T) {
	if (baseURLs{}).pypiBase() != "https://pypi.org" || (baseURLs{}).npmBase() != "https://registry.npmjs.org" {
		t.Fatal("default bases wrong")
	}
	if (baseURLs{pypi: "https://x", npm: "https://y"}).pypiBase() != "https://x" {
		t.Fatal("override base ignored")
	}
}
