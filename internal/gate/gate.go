// Package gate implements the gate engine. Chunk 1 ships Gate 1
// (publication age); G2-G7 land in later chunks behind the same Verdict
// shape so the engine surface does not change.
//
// Fail-closed semantics (SC.6, NFR-001/002, FR-003, binding):
//   - verification failure (registry unreachable, unparseable response,
//     ambiguous spec) -> BLOCK with the override path printed
//   - never warn-and-pass on unverifiable age
//   - unverifiable verdicts are NEVER cached (SB.3)
package gate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/penrush/penrush/internal/cache"
	"github.com/penrush/penrush/internal/config"
	"github.com/penrush/penrush/internal/override"
	"github.com/penrush/penrush/internal/registry"
)

// Decision is a gate outcome.
type Decision string

const (
	Pass         Decision = "pass"
	Block        Decision = "block"
	OverrideUsed Decision = "override_used"
)

// Verdict is one gate's result for one artifact.
type Verdict struct {
	Gate       string // "G1"
	Decision   Decision
	Reason     string
	AgeDays    float64   // -1 when unknown
	ClearAt    time.Time // when a blocked artifact will first pass (zero if n/a)
	SourceURL  string
	Confidence string
	FromCache  bool
}

// Engine wires config, overrides, cache and resolvers.
type Engine struct {
	Config    *config.Config
	Overrides *override.Store
	Cache     *cache.Cache
	Resolvers map[string]registry.Resolver
	Now       func() time.Time // injectable for tests
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// ArtifactKey builds the override/cache key: eco:name (no version — override
// keys are per-artifact, matching the internal hook).
func ArtifactKey(eco, name string) string { return eco + ":" + name }

func cacheKey(eco, name, version string) string {
	if version == "" {
		return eco + ":" + name
	}
	return eco + ":" + name + "@" + version
}

// CheckGate1 runs the publication-age gate for one artifact.
// Order: override -> cache -> live resolve. Every error path returns a BLOCK
// verdict (fail-closed); err is non-nil only for internal invariant failures.
func (e *Engine) CheckGate1(ctx context.Context, eco, name, version string) Verdict {
	now := e.now()
	cooldown := time.Duration(e.Config.Cooldown(eco)) * 24 * time.Hour
	key := ArtifactKey(eco, name)

	// 1. Override (FR-004): an unexpired exact-key override passes the gate —
	//    but only when it APPLIES to the requested version (PR-P2-02). A
	//    version-pinned override approves only the reviewed version; a different
	//    version falls through to the age gate below rather than being silently
	//    waved through (the "reviewed v1.0.0 → freshly-published-malicious v99"
	//    exposure). A version-blind (legacy) override still applies to any
	//    version, preserving v0 UX.
	if e.Overrides != nil && e.Overrides.AppliesTo(key, version, now) {
		o, _ := e.Overrides.Get(key)
		return Verdict{
			Gate:     "G1",
			Decision: OverrideUsed,
			Reason:   fmt.Sprintf("override active for %s (reason: %s, expires %s)", key, o.Reason, o.ExpiresAt),
			AgeDays:  -1,
		}
	}

	// 2. Cache (SB.3).
	if e.Cache != nil {
		if entry, ok := e.Cache.Get(cacheKey(eco, name, version), now); ok {
			pub, perr := time.Parse(time.RFC3339, entry.PublishedAt)
			if perr == nil {
				return e.ageVerdict(eco, name, pub, entry.SourceURL, "cached", cooldown, now, true)
			}
			// Unparseable cached content: fall through to live resolve.
		}
	}

	// 3. Live resolve.
	resolver, ok := e.Resolvers[eco]
	if !ok {
		return Verdict{
			Gate:     "G1",
			Decision: Block,
			Reason:   fmt.Sprintf("no registry client for ecosystem %q in this build (have: npm, pypi, github, cargo, gem, go, docker, mcp) — fail-closed. Override: penrush override add %s --reason \"...\"", eco, key),
			AgeDays:  -1,
		}
	}
	res, err := resolver.Resolve(ctx, name, version)
	if err != nil {
		// Approval-gated artifacts (MCP, SD.9): block pending explicit approval,
		// NOT a fail-closed transport error. The resolver's message already
		// carries the override (= approval) path and any registry enrichment, so
		// it is surfaced verbatim. A preview registry being unreachable degrades
		// to "no enrichment" inside the resolver — it never strands the CLI here.
		if errors.Is(err, registry.ErrApprovalRequired) {
			return Verdict{Gate: "G1", Decision: Block, Reason: err.Error(), AgeDays: -1}
		}
		reason := fmt.Sprintf("cannot verify %s age for %q — fail-closed (FR-003). Override: penrush override add %s --reason \"...\"", eco, name, key)
		if errors.Is(err, registry.ErrNotFound) {
			reason = fmt.Sprintf("%s artifact %q not found in registry — its own red flag (dependency-confusion posture, SD.10). Override: penrush override add %s --reason \"...\"", eco, name, key)
		}
		// NEVER cached (FR-003): fail-closed re-evaluates live every time.
		return Verdict{Gate: "G1", Decision: Block, Reason: reason + " [" + err.Error() + "]", AgeDays: -1}
	}

	v := e.ageVerdict(eco, name, res.PublishedAt, res.SourceURL, res.Confidence, cooldown, now, false)
	// Cache pass/block per SB.3 TTL table. Cache failure is non-fatal.
	if e.Cache != nil {
		_ = e.Cache.Put(cacheKey(eco, name, version), string(v.Decision), res.PublishedAt, res.SourceURL, v.ClearAt, now)
	}
	return v
}

func (e *Engine) ageVerdict(eco, name string, publishedAt time.Time, sourceURL, confidence string, cooldown time.Duration, now time.Time, fromCache bool) Verdict {
	age := now.Sub(publishedAt)
	ageDays := age.Hours() / 24
	clearAt := publishedAt.Add(cooldown)
	if age >= cooldown {
		return Verdict{
			Gate:       "G1",
			Decision:   Pass,
			Reason:     fmt.Sprintf("%s %q published %.1f days ago — clears the %d-day cool-down", eco, name, ageDays, int(cooldown.Hours()/24)),
			AgeDays:    ageDays,
			SourceURL:  sourceURL,
			Confidence: confidence,
			FromCache:  fromCache,
		}
	}
	return Verdict{
		Gate:       "G1",
		Decision:   Block,
		Reason:     fmt.Sprintf("%s %q published %.1f days ago — under the %d-day cool-down. Will pass after %s. Override: penrush override add %s --reason \"...\"", eco, name, ageDays, int(cooldown.Hours()/24), clearAt.UTC().Format("2006-01-02"), ArtifactKey(eco, name)),
		AgeDays:    ageDays,
		ClearAt:    clearAt,
		SourceURL:  sourceURL,
		Confidence: confidence,
		FromCache:  fromCache,
	}
}
