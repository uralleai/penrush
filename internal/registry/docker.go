package registry

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Docker resolves image recency / enforces digest pinning.
//
// SD.8 policy (identical to the internal hook):
//   - Digest-pinned reference (image@sha256:<hex>) PASSES regardless of
//     registry: the digest IS the supply-chain control (content-addressed,
//     non-forgeable). Age is not the gate here — immutability is.
//   - Docker Hub tag reference: GET
//     https://hub.docker.com/v2/repositories/{ns}/{repo}/tags/{tag} ->
//     tag_last_pushed / last_updated + digest (live-verified 2026-06-16,
//     library/alpine:latest). Age is then gate-able by the engine.
//   - Non-Hub tag reference (ghcr.io, quay.io, …): the OCI distribution
//     protocol exposes no publish-timestamp endpoint, so a producer-set
//     `created` field is forgeable and never a sole pass criterion. Tag-only
//     references BLOCK with the digest-discovery hint (resolve via
//     `docker buildx imagetools inspect` / `crane digest`, then pin
//     image@sha256:<digest>).
//
// This resolver returns:
//   - a Resolution with Confidence "digest-pinned" for digest references (the
//     engine treats any sufficiently-old timestamp as pass; digest-pinned
//     resolutions carry the zero-age-but-immutable signal via a far-past
//     PublishedAt so the age gate always clears — the integrity guarantee is
//     the digest, not recency).
//   - a Resolution from the Hub timestamp for Hub tag references.
//   - ErrNotFound / a block-worthy error for unresolvable or non-Hub tag-only
//     references (fail-closed with the digest hint in the message).
type Docker struct {
	Client  *Client
	BaseURL string // default https://hub.docker.com
}

func (d *Docker) Ecosystem() string { return "docker" }

type dockerTagDoc struct {
	LastUpdated   string `json:"last_updated"`
	TagLastPushed string `json:"tag_last_pushed"`
	Digest        string `json:"digest"`
}

// distantPast is used for digest-pinned references so the publication-age gate
// always clears: a content-addressed digest cannot change, so cool-down (a
// proxy for "has anyone had time to notice this is malicious") does not apply —
// the digest is the strong control. Year 2000 is unambiguously past any gate.
var distantPast = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

func (d *Docker) Resolve(ctx context.Context, name, version string) (*Resolution, error) {
	// Reconstruct the full reference. A version that is itself a digest
	// (sha256:...) joins with '@' (image@sha256:...); a plain tag joins with
	// ':'. The CLI passes the digest in the version slot for `image@sha256:...`
	// inputs (it splits on the last '@'/':' — see splitVersion).
	ref := name
	if version != "" {
		if strings.HasPrefix(version, "sha256:") {
			ref = name + "@" + version
		} else {
			ref = name + ":" + version
		}
	}
	img, tag, digest, err := parseDockerRef(ref)
	if err != nil {
		return nil, err
	}

	// Digest pin: the enforced control. Passes on any registry.
	if digest != "" {
		return &Resolution{
			PublishedAt: distantPast,
			SourceURL:   "docker-ref:" + ref,
			Confidence:  "digest-pinned",
		}, nil
	}

	// Tag-only reference. Only Docker Hub exposes a queryable publish time.
	registryHost, repo := splitRegistryHost(img)
	if registryHost != "" {
		// Non-Hub registry, tag-only: digest pinning is the required control.
		return nil, fmt.Errorf("%w: docker %s is a tag-only reference on %s — no publish-timestamp API exists for OCI registries. Pin by digest instead: resolve with `docker buildx imagetools inspect %s` (or `crane digest %s`) and use %s@sha256:<digest>",
			ErrNotFound, ref, registryHost, ref, ref, img)
	}

	// Docker Hub. Normalize bare names to the library/ namespace.
	ns, name2 := splitHubRepo(repo)
	base := d.BaseURL
	if base == "" {
		base = "https://hub.docker.com"
	}
	u := fmt.Sprintf("%s/v2/repositories/%s/%s/tags/%s", base, ns, name2, tag)
	var doc dockerTagDoc
	if err := d.Client.GetJSON(ctx, u, nil, &doc); err != nil {
		return nil, err
	}
	ts := doc.TagLastPushed
	if ts == "" {
		ts = doc.LastUpdated
	}
	if ts == "" {
		return nil, fmt.Errorf("%w: docker %s has no tag_last_pushed/last_updated on Hub", ErrNotFound, ref)
	}
	t, perr := parseRubyTime(ts) // Hub timestamps carry fractional seconds
	if perr != nil {
		return nil, fmt.Errorf("docker: unparseable timestamp %q for %s", ts, ref)
	}
	return &Resolution{
		PublishedAt: t,
		SourceURL:   u,
		Confidence:  "tag-last-pushed",
	}, nil
}

// parseDockerRef splits an image reference into (image, tag, digest).
// Forms: "name", "name:tag", "name@sha256:hex", "name:tag@sha256:hex",
// "host/ns/name:tag". A digest wins: when present, tag is irrelevant for the
// gate. Default tag is "latest".
func parseDockerRef(ref string) (image, tag, digest string, err error) {
	if ref == "" {
		return "", "", "", fmt.Errorf("docker: empty image reference")
	}
	// Digest split first (on '@').
	if at := strings.Index(ref, "@"); at >= 0 {
		image = ref[:at]
		digest = ref[at+1:]
		if !strings.HasPrefix(digest, "sha256:") || len(digest) <= len("sha256:") {
			return "", "", "", fmt.Errorf("docker: malformed digest %q (want sha256:<hex>)", digest)
		}
		// Strip a tag that may precede the digest (image:tag@sha256:…).
		if c := lastColonBeforeSlashSafe(image); c >= 0 {
			image = image[:c]
		}
		if image == "" {
			return "", "", "", fmt.Errorf("docker: digest reference missing image name")
		}
		return image, "", digest, nil
	}
	// Tag split (on the last ':' that is not part of a host:port).
	if c := lastColonBeforeSlashSafe(ref); c >= 0 {
		return ref[:c], ref[c+1:], "", nil
	}
	return ref, "latest", "", nil
}

// lastColonBeforeSlashSafe returns the index of a ':' that separates a tag —
// i.e. a ':' that appears AFTER the final '/'. A ':' in a registry host:port
// (which appears before a '/') is not a tag separator. Returns -1 if none.
func lastColonBeforeSlashSafe(s string) int {
	lastSlash := strings.LastIndex(s, "/")
	colon := strings.LastIndex(s, ":")
	if colon > lastSlash {
		return colon
	}
	return -1
}

// splitRegistryHost separates an explicit registry host from the repository
// path. A host is the first path segment IF it contains a '.' or ':' or equals
// "localhost" (Docker's own heuristic). Returns ("", img) for Docker Hub refs.
func splitRegistryHost(img string) (host, repo string) {
	first, rest, ok := strings.Cut(img, "/")
	if !ok {
		return "", img // bare name, e.g. "alpine"
	}
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return first, rest
	}
	return "", img // e.g. "library/alpine" — Hub namespace, not a host
}

// splitHubRepo maps a Hub repository to (namespace, name). Bare official
// images (no '/') live under the "library" namespace.
func splitHubRepo(repo string) (ns, name string) {
	if n, r, ok := strings.Cut(repo, "/"); ok {
		return n, r
	}
	return "library", repo
}
