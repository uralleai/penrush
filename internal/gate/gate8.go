// Gate 8 — install-time remote-code-execution detection (FR-106), the first
// content-analysis gate. It fetches the package payload, reads its
// install-lifecycle hooks, and statically detects a fetch-remote-then-execute
// pattern.
//
// Gate 8 rides the UNCHANGED gate.Engine / Verdict seam: this file adds a NEW
// Gate8 type + a Check method that RETURNS a gate.Verdict exactly like G1-G7.
// It does NOT modify gate.go's Engine or Verdict (the chunk-2 discipline —
// "one module + wiring, no engine change", architecture delta §V5).
//
// v-next / gated: Gate 8 runs ONLY when explicitly enabled (config
// gate8_enabled). With it disabled the caller never constructs a Gate8, so
// behavior is byte-identical to v0.1.0.
package gate

import (
	"context"
	"fmt"

	"github.com/penrush/penrush/internal/installscan"
)

// PayloadScanner is the Gate-8 payload-scan seam: resolve the artifact,
// SSRF-validate + hardened-fetch it, and return the allowlisted install-hook
// file contents (cleaned path -> bytes), or an error. Every error is
// fail-closed (the gate blocks). The production implementation is
// *payload.Scanner; tests supply a stub. NEVER executes payload code.
type PayloadScanner interface {
	Scan(ctx context.Context, eco, name, version string) (map[string][]byte, error)
}

// Gate8 holds the Gate-8-specific dependencies alongside (not inside) the
// Engine, so the Engine surface in gate.go stays frozen. It reuses the Engine's
// override store, clock, and config through the *Engine pointer.
type Gate8 struct {
	Engine  *Engine
	Scanner PayloadScanner
}

// gate8Ecosystems are the script-bearing ecosystems Gate 8 inspects. Every
// other ecosystem (go, github, mcp) has no install-script mechanism and is
// recorded n/a — never a false block (FR-106 no-false-block EARS).
var gate8Ecosystems = map[string]bool{
	"npm": true, "pypi": true, "cargo": true, "gem": true, "docker": true,
}

// naVerdict / passVerdict / blockVerdict build G8 verdicts on the frozen Verdict
// shape (AgeDays -1: Gate 8 is not an age gate).
func g8Verdict(dec Decision, reason string) Verdict {
	return Verdict{Gate: "G8", Decision: dec, Reason: reason, AgeDays: -1}
}

// Check runs Gate 8 for one artifact and returns a Verdict. priorBlocked is true
// when a cheaper hard gate (e.g. G1 age < cooldown) already blocked — Gate 8
// then SHORT-CIRCUITS with no payload fetch (architecture delta §V1.2: the
// 14-day cool-down naturally defers every expensive scan to survivors, and no
// 5-second tarball fetch is wasted on an already-blocked package).
func (g *Gate8) Check(ctx context.Context, eco, name, version string, priorBlocked bool) Verdict {
	// n/a ecosystems: recorded, never block.
	if !gate8Ecosystems[eco] {
		return g8Verdict(Pass, fmt.Sprintf("G8 n/a — %s has no install-script mechanism", eco))
	}

	// Short-circuit: a cheaper hard gate already blocked → no payload fetch.
	if priorBlocked {
		return g8Verdict(Pass, "G8 skipped — a prior hard gate already blocked this install; no payload fetch (§V1.2)")
	}

	key := ArtifactKey(eco, name)

	// Override (FR-004): an unexpired exact-key override that applies to this
	// version waves Gate 8, exactly as it waves Gate 1. Reuses the existing
	// override store — no new override semantics (delta §V1.3).
	if g.Engine != nil && g.Engine.Overrides != nil && g.Engine.Overrides.AppliesTo(key, version, g.Engine.now()) {
		o, _ := g.Engine.Overrides.Get(key)
		return g8Verdict(OverrideUsed, fmt.Sprintf("override active for %s (reason: %s, expires %s)", key, o.Reason, o.ExpiresAt))
	}

	// Fetch + bounded in-memory scan. ANY error is fail-closed (SSRF reject,
	// decompression bomb, zip-slip, symlink, malformed archive, fetch failure,
	// docker-deferred, timeout) — the gate BLOCKS, never silently passes.
	contents, err := g.Scanner.Scan(ctx, eco, name, version)
	if err != nil {
		return g8Verdict(Block, fmt.Sprintf(
			"cannot statically verify %s %q install-time safety — fail-closed (FR-003/§V4): %v. Override: penrush override add %s --reason \"...\"",
			eco, name, err, key))
	}

	// Locate lifecycle hooks + run the fetch-sink ∧ exec-sink co-occurrence scan.
	hooks := installscan.Locate(eco, contents)
	finding := installscan.Detect(eco, hooks)

	switch finding.Level {
	case installscan.LevelHigh, installscan.LevelFailClosed:
		return g8Verdict(Block, finding.Message(eco, name)+
			fmt.Sprintf(". Override: penrush override add %s --reason \"...\"", key))
	case installscan.LevelMedium:
		// Advisory — does NOT block on Gate 8 (Gate 1 age applies independently).
		return g8Verdict(Pass, finding.Message(eco, name))
	case installscan.LevelNA:
		return g8Verdict(Pass, finding.Message(eco, name))
	default: // LevelNone
		return g8Verdict(Pass, fmt.Sprintf("G8 clean — %s %q declares no install-lifecycle hook", eco, name))
	}
}
