// Package config loads/saves ~/.penrush/config.json.
//
// Architecture ref: SB.4. JSON only at v0 (SL-6 zero-deps ruling — no YAML).
// Defaults: cooldown_days 14 per ecosystem, on_internal_error "block"
// (SL-4 ratified — a crashing gate is otherwise a bypass primitive, SC.6),
// telemetry "off" (SI: there is nothing to turn on; the field exists so the
// posture is visible and greppable).
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// SchemaVersion of config.json.
const SchemaVersion = 1

// DefaultCooldownDays is the global default age gate.
const DefaultCooldownDays = 14

// DefaultGate8Enabled is the compiled default for the FR-106 content-analysis
// gate when config.json does not set gate8_enabled. It is TRUE as of v0.2.0
// (the FR-106 field-test release): a fresh install AND an upgraded v0.1.0
// install (whose config predates the field) both run Gate 8 by default, so a
// normal `penrush check` exercises install-time remote-code detection. Set
// "gate8_enabled": false in config.json to opt out (restores the
// byte-identical-to-v0.1.0 metadata-only path). Gate 8 is additive and
// fail-closed — it never loosens Gate 1.
const DefaultGate8Enabled = true

// MinCooldownDays is the hard floor below which a configured cooldown is
// clamped up (PR-P2-01). A config-set cooldown_days of 0 would turn Gate 1 —
// the only enforced gate at v0 — into a global ALLOW for every freshly
// published package, achieving the architecturally-rejected `npm:*` wildcard
// override through config and bypassing every override-abuse control (no
// reason, no expiry, no per-artifact scope, no audit event). Per architecture
// §C.3 row 4 ("policy may only tighten, never loosen below the compiled
// default"), a value below this floor is never silently honored: Cooldown
// clamps it up to the floor and reports the clamp so the load can be audited.
const MinCooldownDays = 1

// Valid on_internal_error modes.
const (
	InternalErrorBlock = "block"
	InternalErrorAllow = "allow"
)

// Config mirrors config.json.
type Config struct {
	SchemaVersion   int            `json:"schema_version"`
	CooldownDays    map[string]int `json:"cooldown_days"`     // per-ecosystem; "default" key is the fallback
	OnInternalError string         `json:"on_internal_error"` // "block" (default) | "allow"
	Telemetry       string         `json:"telemetry"`         // always "off" at v0
	GithubTokenEnv  string         `json:"github_token_env"`  // opt-in env-var NAME to read a GitHub token from (never the token itself)
	CacheHMACKey    string         `json:"cache_hmac_key"`    // per-install random key, hex (SB.3 cache integrity)
	// Gate8Enabled is the three-state opt-in for the FR-106 / Chunk-6
	// content-analysis gate: fetch the package payload and statically scan its
	// install-lifecycle hooks for remote-code-on-install.
	//
	//   nil    (field absent) → the compiled default, DefaultGate8Enabled. A
	//                           config written by v0.1.0 has no such field, so on
	//                           upgrade to v0.2.0 it resolves to the v0.2.0
	//                           default (ON) without a rewrite.
	//   *true  → enabled.
	//   *false → explicitly disabled: the byte-identical-to-v0.1.0 metadata-only
	//            path (Gate 8 is never constructed and no payload is ever fetched).
	//
	// Resolve via Gate8IsEnabled(); do NOT dereference this pointer directly.
	//
	// v0.2.0 FIELD-TEST: the default is ON. FR-106 is a NEW capability pending
	// its own PH-2b external pentest; the CLI surfaces that on every G8 verdict.
	Gate8Enabled *bool `json:"gate8_enabled,omitempty"`
}

// Default returns a fresh config with a newly generated cache HMAC key.
func Default() (*Config, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating cache HMAC key: %w", err)
	}
	gate8 := DefaultGate8Enabled // written explicitly so a fresh config.json shows the posture
	return &Config{
		SchemaVersion:   SchemaVersion,
		CooldownDays:    map[string]int{"default": DefaultCooldownDays},
		OnInternalError: InternalErrorBlock,
		Telemetry:       "off",
		GithubTokenEnv:  "",
		CacheHMACKey:    hex.EncodeToString(key),
		Gate8Enabled:    &gate8,
	}, nil
}

// Gate8IsEnabled resolves the three-state gate8_enabled setting: an explicit
// value wins; an absent value (nil — e.g. a config written by v0.1.0, which had
// no such field) falls back to the compiled DefaultGate8Enabled. Callers MUST
// use this rather than dereferencing Gate8Enabled directly.
func (c *Config) Gate8IsEnabled() bool {
	if c.Gate8Enabled == nil {
		return DefaultGate8Enabled
	}
	return *c.Gate8Enabled
}

// Load reads config from path. Missing file returns (nil, os.ErrNotExist).
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if c.OnInternalError == "" {
		c.OnInternalError = InternalErrorBlock
	}
	if c.OnInternalError != InternalErrorBlock && c.OnInternalError != InternalErrorAllow {
		return nil, fmt.Errorf("config: on_internal_error must be %q or %q, got %q",
			InternalErrorBlock, InternalErrorAllow, c.OnInternalError)
	}
	if c.CooldownDays == nil {
		c.CooldownDays = map[string]int{"default": DefaultCooldownDays}
	}
	if c.Telemetry == "" {
		c.Telemetry = "off"
	}
	return &c, nil
}

// Save writes config to path (0600).
func (c *Config) Save(path string) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

// Cooldown returns the cooldown window in days for an ecosystem, falling
// back to the "default" key, then the compiled default. Any value below
// MinCooldownDays is clamped UP to the floor (PR-P2-01) — config may tighten
// the gate (raise the cooldown) but may never loosen it below the floor.
func (c *Config) Cooldown(ecosystem string) int {
	d, _ := c.cooldownRaw(ecosystem)
	if d < MinCooldownDays {
		return MinCooldownDays
	}
	return d
}

// cooldownRaw returns the raw configured value (pre-clamp) and whether it came
// from an explicit config key (true) or the compiled default (false).
func (c *Config) cooldownRaw(ecosystem string) (days int, fromConfig bool) {
	if d, ok := c.CooldownDays[ecosystem]; ok && d >= 0 {
		return d, true
	}
	if d, ok := c.CooldownDays["default"]; ok && d >= 0 {
		return d, true
	}
	return DefaultCooldownDays, false
}

// LooseningClamps returns, for the given ecosystems, the keys whose configured
// cooldown was clamped UP because it was below MinCooldownDays. A non-empty
// result means config.json attempted to loosen the gate below the floor — the
// caller MUST emit an audit `policy_changed`/block event so the attempt is
// never traceless (PR-P2-01). The map value is the rejected raw value.
func (c *Config) LooseningClamps(ecosystems []string) map[string]int {
	out := map[string]int{}
	keys := append([]string{"default"}, ecosystems...)
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k] {
			continue
		}
		seen[k] = true
		if raw, ok := c.CooldownDays[k]; ok && raw >= 0 && raw < MinCooldownDays {
			out[k] = raw
		}
	}
	return out
}
