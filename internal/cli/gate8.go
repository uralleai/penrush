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
// It returns nil ONLY when Gate 8 is explicitly disabled (gate8_enabled:false) —
// the caller then runs exactly the v0.1.0 metadata-only path, byte-for-byte.
// The v0.2.0 default is ON (config.DefaultGate8Enabled), so a normal check
// exercises install-time remote-code detection. Gate 8 is purely additive and
// fail-closed; it never loosens Gate 1.
func (e *Env) buildGate8(eng *gate.Engine, cfg *config.Config) *gate.Gate8 {
	if !cfg.Gate8IsEnabled() {
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
	fmt.Fprintf(e.Stdout, "  note:   %s\n", e.accent(gate8FieldTestNotice))
}

// gate8FieldTestNotice is the one-line honesty banner surfaced on every Gate-8
// verdict in this FIELD-TEST / PRE-AUDIT release (v0.2.0). Gate 8 (FR-106) is a
// NEW capability that has not yet passed its own formal external security
// pentest (PH-2b); the notice travels with the output so a field-test user is
// never misled into treating it as an audited guarantee.
const gate8FieldTestNotice = "FIELD-TEST (v0.2.0, pre-audit): Gate 8 (FR-106) install-time remote-code detection is a NEW capability pending its formal external security pentest (PH-2b)."
