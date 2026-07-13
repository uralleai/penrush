package payload

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// SSRF defense on the artifact-download URL (delta §V4.6). The URL is derived
// from registry metadata (TB2, untrusted) — a malicious registry response could
// point the fetch at an internal/private address. Two layers:
//
//  1. STATIC (ValidateFetchURL): https-only, per-ecosystem host allowlist,
//     no embedded credentials.
//  2. DYNAMIC (the dialer Control below): at connect time, on the ACTUAL
//     resolved IP, reject private / loopback / link-local / ULA / multicast /
//     unspecified / cloud-metadata addresses. Checking the resolved IP (not the
//     hostname) defeats DNS-rebinding — a hostname that passes the allowlist but
//     resolves to 169.254.169.254 is still refused.

var (
	ErrNotHTTPS         = errors.New("payload: artifact URL must be https (no insecure fetch exists)")
	ErrHostNotAllowed   = errors.New("payload: artifact host is not on the per-ecosystem allowlist (SSRF defense)")
	ErrURLCredentials   = errors.New("payload: artifact URL must not embed credentials")
	ErrPrivateAddress   = errors.New("payload: artifact host resolves to a private/loopback/link-local address (SSRF defense)")
	ErrArtifactTooLarge = errors.New("payload: artifact exceeds the compressed-size cap")
)

// hostAllowlist maps each ecosystem to the set of hosts (exact or *.suffix) its
// artifacts may be downloaded from. A forged URL to any other host is refused
// before a single packet leaves the machine.
var hostAllowlist = map[string][]string{
	"npm":   {"registry.npmjs.org", "*.npmjs.org"},
	"pypi":  {"files.pythonhosted.org", "pypi.org"},
	"cargo": {"static.crates.io", "crates.io"},
	"gem":   {"rubygems.org", "*.rubygems.org"},
	// docker payload fetch (config blob) is resolved against the reference's own
	// registry host; it is validated separately in the scanner. No blanket entry.
}

// hostAllowed reports whether host is permitted for ecosystem eco.
func hostAllowed(eco, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pat := range hostAllowlist[eco] {
		if strings.HasPrefix(pat, "*.") {
			if strings.HasSuffix(host, pat[1:]) && len(host) > len(pat)-1 {
				return true
			}
		} else if host == pat {
			return true
		}
	}
	return false
}

// ValidateFetchURL applies the STATIC SSRF checks. It must pass before any
// network call.
func ValidateFetchURL(eco, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("payload: unparseable artifact URL %q: %w", raw, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%w: %q", ErrNotHTTPS, raw)
	}
	if u.User != nil {
		return fmt.Errorf("%w: %q", ErrURLCredentials, raw)
	}
	if !hostAllowed(eco, u.Hostname()) {
		return fmt.Errorf("%w: eco=%s host=%q", ErrHostNotAllowed, eco, u.Hostname())
	}
	return nil
}

// isPrivateIP reports whether an IP is in a range that must never be reachable
// via an artifact fetch (SSRF sink). Covers loopback, link-local (incl. the
// 169.254.169.254 cloud-metadata address), private RFC1918/ULA, multicast, and
// the unspecified address.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true // unresolvable → refuse (fail-closed)
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	// Explicit cloud-metadata guard (belt and braces; 169.254.169.254 is
	// already link-local, but IPv6 fd00::/8 ULA is caught by IsPrivate).
	if v4 := ip.To4(); v4 != nil && v4[0] == 169 && v4[1] == 254 {
		return true
	}
	return false
}

// dialerControl is the net.Dialer.Control hook: it runs after DNS resolution
// with the concrete address about to be connected. It rejects any private
// address (§V4.6 dynamic layer, DNS-rebinding-safe).
func dialerControl(_ string, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if isPrivateIP(net.ParseIP(host)) {
		return fmt.Errorf("%w: %s", ErrPrivateAddress, host)
	}
	return nil
}

// Fetcher fetches an artifact over the hardened, SSRF-guarded transport, capped
// at maxCompressed bytes (§V4.8 bandwidth bound). The returned bytes are read
// into memory bounded by that cap — never streamed to disk.
type Fetcher struct {
	hc            *http.Client
	MaxCompressed int64
}

// NewFetcher builds the hardened fetcher: https-only redirects (also re-guarded
// against private IPs on each hop), the private-IP-reject dialer, and a total
// wall-clock budget (§V4.7 dedicated Gate-8 budget lives in the scanner; this
// is the transport ceiling).
func NewFetcher() *Fetcher {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: dialerControl}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		Proxy:                 nil, // no proxy — an env proxy could bypass the IP guard
		ForceAttemptHTTP2:     true,
	}
	return &Fetcher{
		hc: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if req.URL.Scheme != "https" {
					return ErrNotHTTPS
				}
				if len(via) >= 5 {
					return errors.New("payload: too many redirects")
				}
				return nil
			},
		},
		MaxCompressed: 64 << 20, // 64 MiB compressed download ceiling
	}
}

// NewFetcherWithHTTP wraps a caller-supplied client (test fixtures use
// httptest.NewTLSServer's client). The compressed cap still applies.
func NewFetcherWithHTTP(hc *http.Client, maxCompressed int64) *Fetcher {
	return &Fetcher{hc: hc, MaxCompressed: maxCompressed}
}

// Fetch downloads url (already ValidateFetchURL-checked by the caller) and
// returns the bytes, refusing anything past the compressed cap.
func (f *Fetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "penrush-gate8/0.1")
	resp, err := f.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("payload: artifact fetch got status %d for %s", resp.StatusCode, url)
	}
	// Read at most cap+1 so an over-cap body is detected, not silently truncated.
	data, err := io.ReadAll(io.LimitReader(resp.Body, f.MaxCompressed+1))
	if err != nil {
		return nil, fmt.Errorf("payload: artifact read: %w", err)
	}
	if int64(len(data)) > f.MaxCompressed {
		return nil, ErrArtifactTooLarge
	}
	return data, nil
}
