package cli

// INT-01 regression + lock-step guard. The download site's verification recipe
// (site/index.html) is the ONLY verification guidance an anonymous user sees
// (the repo/docs are PH-2-gated). Before the fix it dropped
// --certificate-identity-regexp from the cosign Check 2 (accepting a signature
// minted by ANY GitHub Actions workflow in ANY repo) and --source-tag from the
// SLSA Check 3 (accepting provenance from any tag). This test asserts the site
// recipe carries the identity pin and source-tag, and that the critical flags
// stay in lock-step with docs/RELEASE.md so they cannot silently drift apart.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	// internal/cli/<this> -> repo root is two dirs up.
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return string(b)
}

func TestSiteVerificationRecipeIsIdentityPinned(t *testing.T) {
	site := repoFile(t, filepath.Join("site", "index.html"))
	rel := repoFile(t, filepath.Join("docs", "RELEASE.md"))

	// The critical flags that constrain WHO could have signed / built the
	// artifact. Each MUST appear in BOTH the site recipe and docs/RELEASE.md.
	critical := []struct {
		name   string
		needle string
	}{
		{"cosign identity pin", "--certificate-identity-regexp"},
		{"cosign OIDC issuer", "--certificate-oidc-issuer"},
		{"slsa source tag", "--source-tag"},
		{"slsa source uri", "--source-uri"},
		{"release workflow path in identity regex", "workflows/release"},
	}
	for _, c := range critical {
		if !strings.Contains(site, c.needle) {
			t.Errorf("INT-01: site/index.html verification recipe is missing %q (%s) — under-constrained, would accept a forged signature/provenance", c.needle, c.name)
		}
		if !strings.Contains(rel, c.needle) {
			t.Errorf("lock-step: docs/RELEASE.md is missing %q (%s)", c.needle, c.name)
		}
	}

	// Negative guard: the OIDC issuer must never appear WITHOUT an identity pin
	// in the site (the exact INT-01 mistake).
	if strings.Contains(site, "--certificate-oidc-issuer") && !strings.Contains(site, "--certificate-identity-regexp") {
		t.Error("INT-01: site recipe pins the OIDC issuer but not the certificate identity — any GitHub Actions workflow's signature would verify")
	}
}
