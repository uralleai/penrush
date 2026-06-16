package registry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ErrApprovalRequired signals an artifact whose policy is "explicit human
// approval", independent of any age check. The gate treats it as a BLOCK (an
// un-approved MCP add does not pass) but renders an approval-gated reason
// rather than a fail-closed transport error — so an unreachable preview
// registry NEVER bricks legitimate use: approval (via `penrush override add
// mcp:<server> --reason "..."`) is the path whether the registry is up or not.
var ErrApprovalRequired = errors.New("explicit approval required")

// MCP gates MCP-server adds.
//
// SD.9: the official MCP registry (registry.modelcontextprotocol.io) is
// PREVIEW — "breaking changes or data resets may occur", with an API freeze at
// v0.1 (primary source: github.com/modelcontextprotocol/registry; re-verified
// 2026-06-16: still no GA, API-freeze v0.1, data resets possible). Therefore:
//
//   - NO hard dependency on the preview API. The gate decision for an MCP add
//     is "explicit-approval-gated" (mirroring the internal hook: block + require
//     the human's explicit approval) REGARDLESS of registry reachability.
//   - Registry metadata is fetched best-effort as ENRICHMENT only (server
//     provenance / publish info shown in the approval prompt when available),
//     never as a silent pass and never as a hard fail. A timeout/5xx/404 on the
//     preview registry degrades silently to "no enrichment" — it does not turn
//     into a transport-block that strands the CLI.
//
// When the registry GAs, age-checking upgrades from enrichment to enforcement —
// a config flip, not a redesign.
type MCP struct {
	Client  *Client
	BaseURL string // default https://registry.modelcontextprotocol.io
}

func (m *MCP) Ecosystem() string { return "mcp" }

// mcpEnrichment is the subset of the preview v0.1 server record we surface if
// the (unstable) registry happens to answer. Decoding is lenient by design.
type mcpEnrichment struct {
	Servers []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Version     string `json:"version"`
		Repository  struct {
			URL string `json:"url"`
		} `json:"repository"`
	} `json:"servers"`
}

func (m *MCP) Resolve(ctx context.Context, name, version string) (*Resolution, error) {
	// Best-effort enrichment with a tight, independent timeout so a hung
	// preview registry cannot consume the gate budget. Errors are swallowed:
	// the decision is approval-gated either way.
	enrich := m.fetchEnrichment(ctx, name)

	msg := fmt.Sprintf("MCP server %q requires explicit approval before it is added (the MCP registry is preview/unstable — PenRUSH does not auto-pass MCP adds). Approve with: penrush override add mcp:%s --reason \"...\"",
		name, name)
	if enrich != "" {
		msg += " | registry enrichment: " + enrich
	} else {
		msg += " | registry enrichment unavailable (preview registry unreachable or no record) — approval still required, not a transport failure"
	}
	return nil, fmt.Errorf("%w: %s", ErrApprovalRequired, msg)
}

// fetchEnrichment does a single short, failure-tolerant lookup. Any error
// (registry preview down, 404, decode failure) returns "" — never propagated.
func (m *MCP) fetchEnrichment(parent context.Context, name string) string {
	if m.Client == nil {
		return ""
	}
	base := m.BaseURL
	if base == "" {
		base = "https://registry.modelcontextprotocol.io"
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	u := base + "/v0/servers?search=" + url.QueryEscape(name)
	var doc mcpEnrichment
	if err := m.Client.GetJSON(ctx, u, nil, &doc); err != nil {
		return ""
	}
	for _, s := range doc.Servers {
		if s.Name == name || strings.EqualFold(s.Name, name) {
			parts := []string{}
			if s.Version != "" {
				parts = append(parts, "v"+s.Version)
			}
			if s.Repository.URL != "" {
				parts = append(parts, s.Repository.URL)
			}
			if len(parts) > 0 {
				return strings.Join(parts, " ")
			}
			return "record found"
		}
	}
	return ""
}
