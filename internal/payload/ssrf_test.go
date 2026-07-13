package payload

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateFetchURL(t *testing.T) {
	cases := []struct {
		eco, url string
		wantErr  error
	}{
		{"npm", "https://registry.npmjs.org/x/-/x-1.0.0.tgz", nil},
		{"npm", "https://foo.npmjs.org/x.tgz", nil}, // *.npmjs.org
		{"pypi", "https://files.pythonhosted.org/packages/x.tar.gz", nil},
		{"cargo", "https://static.crates.io/crates/x/x-1.0.0.crate", nil},
		{"gem", "https://rubygems.org/downloads/x-1.0.0.gem", nil},
		// SSRF / hardening rejections:
		{"npm", "http://registry.npmjs.org/x.tgz", ErrNotHTTPS},
		{"npm", "https://evil.example.com/x.tgz", ErrHostNotAllowed},
		{"npm", "https://169.254.169.254/x.tgz", ErrHostNotAllowed}, // forged host: not on allowlist
		{"npm", "https://user:pass@registry.npmjs.org/x.tgz", ErrURLCredentials},
		{"pypi", "https://registry.npmjs.org/x.tgz", ErrHostNotAllowed}, // right host, wrong eco
	}
	for _, c := range cases {
		err := ValidateFetchURL(c.eco, c.url)
		if c.wantErr == nil {
			if err != nil {
				t.Errorf("ValidateFetchURL(%s,%s) = %v, want nil", c.eco, c.url, err)
			}
			continue
		}
		if !errors.Is(err, c.wantErr) {
			t.Errorf("ValidateFetchURL(%s,%s) = %v, want %v", c.eco, c.url, err, c.wantErr)
		}
	}
}

// TestDialerControl is the DYNAMIC SSRF layer (DNS-rebinding-safe): it runs on
// the RESOLVED IP. A hostname that passes the static allowlist but resolves to a
// private address is still refused here (PA-4).
func TestDialerControl(t *testing.T) {
	private := []string{"127.0.0.1:443", "10.0.0.5:443", "192.168.1.1:443", "169.254.169.254:80", "[::1]:443", "[fd00::1]:443", "0.0.0.0:443"}
	for _, a := range private {
		if err := dialerControl("tcp", a, nil); !errors.Is(err, ErrPrivateAddress) {
			t.Errorf("dialerControl(%s) = %v, want ErrPrivateAddress", a, err)
		}
	}
	public := []string{"8.8.8.8:443", "1.1.1.1:443"}
	for _, a := range public {
		if err := dialerControl("tcp", a, nil); err != nil {
			t.Errorf("dialerControl(%s) = %v, want nil", a, err)
		}
	}
}

func TestIsPrivateIP(t *testing.T) {
	priv := []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.169.254", "::1", "fd00::1", "0.0.0.0", "ff02::1"}
	for _, s := range priv {
		if !isPrivateIP(net.ParseIP(s)) {
			t.Errorf("isPrivateIP(%s) = false, want true", s)
		}
	}
	pub := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1::"}
	for _, s := range pub {
		if isPrivateIP(net.ParseIP(s)) {
			t.Errorf("isPrivateIP(%s) = true, want false", s)
		}
	}
	if !isPrivateIP(nil) {
		t.Error("nil IP must be treated as private (fail-closed)")
	}
}

// TestFetcher_CompressedCap: the fetch refuses a body past the compressed cap
// (§V4.8 bandwidth bound). Uses httptest (the fetcher's client is injected, so
// the private-IP dialer is bypassed here — that layer is covered separately).
func TestFetcher_CompressedCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("A", 10000)))
	}))
	defer srv.Close()
	f := NewFetcherWithHTTP(srv.Client(), 1000) // cap below body size
	_, err := f.Fetch(context.Background(), srv.URL)
	if !errors.Is(err, ErrArtifactTooLarge) {
		t.Fatalf("want ErrArtifactTooLarge, got %v", err)
	}
	// Under the cap: succeeds.
	f2 := NewFetcherWithHTTP(srv.Client(), 1<<20)
	b, err := f2.Fetch(context.Background(), srv.URL)
	if err != nil || len(b) != 10000 {
		t.Fatalf("under-cap fetch failed: n=%d err=%v", len(b), err)
	}
}
