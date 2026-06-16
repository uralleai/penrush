package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Mirrors the live-verified proxy.golang.org .info shape (2026-06-16).
const testifyInfoFixture = `{"Version":"v1.9.0","Time":"2024-02-29T14:36:18Z","Origin":{"VCS":"git","URL":"https://github.com/stretchr/testify","Ref":"refs/tags/v1.9.0","Hash":"bb548d04"}}`

func TestGoModResolve(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/github.com/stretchr/testify/@v/v1.9.0.info"
		if r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		w.Write([]byte(testifyInfoFixture))
	}))
	defer srv.Close()
	g := &GoMod{Client: newFixtureClient(srv), BaseURL: srv.URL}
	res, err := g.Resolve(context.Background(), "github.com/stretchr/testify", "v1.9.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := time.Date(2024, 2, 29, 14, 36, 18, 0, time.UTC)
	if !res.PublishedAt.Equal(want) {
		t.Errorf("PublishedAt = %v, want %v", res.PublishedAt, want)
	}
}

func TestGoModCaseEscaping(t *testing.T) {
	var gotPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte(`{"Version":"v1.0.0","Time":"2024-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()
	g := &GoMod{Client: newFixtureClient(srv), BaseURL: srv.URL}
	// Uppercase in the module path must be '!'-escaped (GOPROXY protocol).
	_, err := g.Resolve(context.Background(), "github.com/Azure/azure-sdk-for-go", "v1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !strings.Contains(gotPath, "github.com/!azure/azure-sdk-for-go") {
		t.Errorf("uppercase not '!'-escaped: path = %q", gotPath)
	}
}

func TestGoModRejectsLatest(t *testing.T) {
	g := &GoMod{Client: nil, BaseURL: "https://unused.example"}
	_, err := g.Resolve(context.Background(), "github.com/stretchr/testify", "latest")
	if err == nil || !strings.Contains(err.Error(), "@latest is forbidden") {
		t.Fatalf("@latest must be rejected at the resolver (lock-file rule), got %v", err)
	}
}

func TestGoModRejectsNoVersion(t *testing.T) {
	g := &GoMod{Client: nil}
	_, err := g.Resolve(context.Background(), "github.com/stretchr/testify", "")
	if err == nil || !strings.Contains(err.Error(), "exact version is required") {
		t.Fatalf("empty version must be rejected, got %v", err)
	}
}

func TestGoMod404Blocks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	g := &GoMod{Client: newFixtureClient(srv), BaseURL: srv.URL}
	_, err := g.Resolve(context.Background(), "github.com/nope/nope", "v9.9.9")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 must be ErrNotFound, got %v", err)
	}
}

func TestGoModEmptyTimeBlocks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"v1.0.0"}`)) // no Time field
	}))
	defer srv.Close()
	g := &GoMod{Client: newFixtureClient(srv), BaseURL: srv.URL}
	_, err := g.Resolve(context.Background(), "github.com/x/y", "v1.0.0")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing Time must fail closed as ErrNotFound, got %v", err)
	}
}

func TestEscapeModulePath(t *testing.T) {
	cases := map[string]string{
		"github.com/stretchr/testify": "github.com/stretchr/testify",
		"github.com/Azure/foo":        "github.com/!azure/foo",
		"github.com/BurntSushi/toml":  "github.com/!burnt!sushi/toml",
		"v1.9.0":                      "v1.9.0",
	}
	for in, want := range cases {
		if got := escapeModulePath(in); got != want {
			t.Errorf("escapeModulePath(%q) = %q, want %q", in, got, want)
		}
	}
}
