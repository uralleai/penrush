package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMCPAlwaysApprovalRequired: an MCP add is approval-gated regardless of the
// (preview) registry being reachable — the decision never silently passes.
func TestMCPAlwaysApprovalRequired(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"servers":[]}`)) // reachable, but no matching record
	}))
	defer srv.Close()
	m := &MCP{Client: newFixtureClient(srv), BaseURL: srv.URL}
	_, err := m.Resolve(context.Background(), "io.example/some-server", "")
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("MCP must return ErrApprovalRequired, got %v", err)
	}
	if !strings.Contains(err.Error(), "penrush override add mcp:") {
		t.Errorf("approval message must carry the override (approval) path, got %q", err.Error())
	}
}

// TestMCPEnrichmentWhenReachable: a matching registry record is surfaced as
// enrichment in the approval message.
func TestMCPEnrichmentWhenReachable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"servers":[{"name":"io.example/srv","version":"1.2.3","repository":{"url":"https://github.com/example/srv"}}]}`))
	}))
	defer srv.Close()
	m := &MCP{Client: newFixtureClient(srv), BaseURL: srv.URL}
	_, err := m.Resolve(context.Background(), "io.example/srv", "")
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("still approval-gated even with enrichment, got %v", err)
	}
	if !strings.Contains(err.Error(), "v1.2.3") || !strings.Contains(err.Error(), "github.com/example/srv") {
		t.Errorf("enrichment (version + repo) not surfaced: %q", err.Error())
	}
}

// TestMCPDegradesWhenRegistryUnreachable: the critical MCP-preview behavior —
// a 5xx/unreachable preview registry must NOT become a transport-block. It
// degrades to approval-required with "enrichment unavailable". This is what
// keeps an unstable preview registry from bricking legitimate use.
func TestMCPDegradesWhenRegistryUnreachable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // preview registry down
	}))
	defer srv.Close()
	m := &MCP{Client: newFixtureClient(srv), BaseURL: srv.URL}
	_, err := m.Resolve(context.Background(), "io.example/srv", "")
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("unreachable preview registry must still be ErrApprovalRequired (not a transport block), got %v", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatal("MCP must never surface a registry transport error as the gate decision")
	}
	if !strings.Contains(err.Error(), "enrichment unavailable") {
		t.Errorf("degradation notice missing: %q", err.Error())
	}
}

// TestMCPNoClientStillApprovalGated: even with no HTTP client at all (fully
// offline), MCP is approval-gated, never crashing or passing.
func TestMCPNoClientStillApprovalGated(t *testing.T) {
	m := &MCP{Client: nil}
	_, err := m.Resolve(context.Background(), "io.example/srv", "")
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("offline MCP must be approval-gated, got %v", err)
	}
}
