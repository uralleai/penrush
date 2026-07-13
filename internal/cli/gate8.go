package cli

import (
	"context"
	"fmt"

	"github.com/penrush/penrush/internal/config"
	"github.com/penrush/penrush/internal/gate"
	"github.com/penrush/penrush/internal/payload"
	"github.com/penrush/penrush/internal/registry"
)

// buildGate8 constructs the Gate-8 rider (FR-106) when it is enabled in config.
// It returns nil when Gate 8 is DISABLED (the default) — the caller then runs
// exactly the v0.1.0 metadata-only path, byte-for-byte. Gate 8 never alters the
// launched v0 behavior; it is purely additive and opt-in.
func (e *Env) buildGate8(eng *gate.Engine, cfg *config.Config) *gate.Gate8 {
	if !cfg.Gate8Enabled {
		return nil
	}
	if e.Gate8Scanner != nil {
		return &gate.Gate8{Engine: eng, Scanner: e.Gate8Scanner}
	}
	registry.Version = Version
	var client *registry.Client
	if e.NewClient != nil {
		client = e.NewClient()
	} else {
		client = registry.NewClient()
	}
	meta := func(ctx context.Context, url string, v any) error {
		return client.GetJSON(ctx, url, nil, v)
	}
	return &gate.Gate8{Engine: eng, Scanner: payload.NewScanner(meta)}
}

// printGate8Verdict renders the Gate-8 result block (content-analysis gate).
// A BLOCK carries the finding message + override path; a Pass shows the
// advisory/clean/n-a reason.
func (e *Env) printGate8Verdict(eco, name, version string, v gate.Verdict) {
	artifact := name
	if version != "" {
		artifact = name + "@" + version
	}
	switch v.Decision {
	case gate.Pass:
		fmt.Fprintf(e.Stdout, "%s %s:%s\n", e.label("G8 PASS", v.Decision), eco, artifact)
	case gate.OverrideUsed:
		fmt.Fprintf(e.Stdout, "%s %s:%s\n", e.label("G8 OVERRIDE", v.Decision), eco, artifact)
	default:
		fmt.Fprintf(e.Stdout, "%s %s:%s\n", e.label("G8 BLOCK", v.Decision), eco, artifact)
	}
	fmt.Fprintf(e.Stdout, "  gate:   %s (install-time content analysis, FR-106)\n", v.Gate)
	fmt.Fprintf(e.Stdout, "  reason: %s\n", v.Reason)
}
