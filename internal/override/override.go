// Package override implements the override store (~/.penrush/overrides.json).
//
// Architecture ref: SB.1 + SC.4 (override-abuse resistance, consolidated):
//   - reason MANDATORY (FR-004)
//   - 30-day default expiry; expires_at never null at v0 (anti-ceremonial-
//     gate control R-15) — the internal hook allows non-expiring overrides,
//     the product does not (deliberate divergence)
//   - scope "exact" only — wildcard keys are architecturally rejected (SC.4)
//   - approver field present now as the v1 team-mode seam (FR-103)
//
// Key format identical to the internal hook: npm:<name>, pypi:<name>,
// crates:<name>, gem:<name>, github:<owner>/<repo>, docker:<image>,
// go:<module>, mcp:<server>.
package override

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// SchemaVersion of overrides.json.
const SchemaVersion = 1

// DefaultTTL is the default override lifetime.
const DefaultTTL = 30 * 24 * time.Hour

// MaxTTL is the hard ceiling (SC.4: 30-day max expiry, no permanent overrides).
const MaxTTL = 30 * 24 * time.Hour

// knownEcosystems for key validation.
var knownEcosystems = map[string]bool{
	"npm": true, "pypi": true, "crates": true, "gem": true,
	"github": true, "docker": true, "go": true, "mcp": true,
}

// Override is one stored override (SB.1 schema).
type Override struct {
	Reason    string  `json:"reason"`
	CreatedAt string  `json:"created_at"`
	ExpiresAt string  `json:"expires_at"`
	Approver  *string `json:"approver"` // v1 team-mode seam; always null at v0
	Scope     string  `json:"scope"`    // always "exact" at v0
}

// Store mirrors overrides.json.
type Store struct {
	SchemaVersion int                 `json:"schema_version"`
	Overrides     map[string]Override `json:"overrides"`
	path          string
}

// Load reads (or initializes, if missing) the store at path.
func Load(path string) (*Store, error) {
	s := &Store{SchemaVersion: SchemaVersion, Overrides: map[string]Override{}, path: path}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if s.Overrides == nil {
		s.Overrides = map[string]Override{}
	}
	s.path = path
	return s, nil
}

// ValidateKey enforces the exact-key format and rejects wildcards.
func ValidateKey(key string) error {
	eco, name, ok := strings.Cut(key, ":")
	if !ok || name == "" {
		return fmt.Errorf("override key must be <ecosystem>:<artifact>, got %q", key)
	}
	if !knownEcosystems[eco] {
		return fmt.Errorf("unknown ecosystem %q in override key (known: npm, pypi, crates, gem, github, docker, go, mcp)", eco)
	}
	if strings.ContainsAny(name, "*?") {
		return fmt.Errorf("wildcard overrides are not supported (SC.4): %q", key)
	}
	return nil
}

// Add records an override. Reason is mandatory; ttl<=0 uses DefaultTTL;
// ttl>MaxTTL is clamped to MaxTTL.
func (s *Store) Add(key, reason string, ttl time.Duration, now time.Time) (Override, error) {
	if err := ValidateKey(key); err != nil {
		return Override{}, err
	}
	if strings.TrimSpace(reason) == "" {
		return Override{}, errors.New("override reason is mandatory (FR-004)")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl > MaxTTL {
		ttl = MaxTTL
	}
	o := Override{
		Reason:    reason,
		CreatedAt: now.UTC().Format(time.RFC3339),
		ExpiresAt: now.UTC().Add(ttl).Format(time.RFC3339),
		Approver:  nil,
		Scope:     "exact",
	}
	s.Overrides[key] = o
	return o, s.save()
}

// Active reports whether key has an unexpired override.
func (s *Store) Active(key string, now time.Time) bool {
	o, ok := s.Overrides[key]
	if !ok {
		return false
	}
	exp, err := time.Parse(time.RFC3339, o.ExpiresAt)
	if err != nil {
		return false // unparseable expiry = inactive (fail closed)
	}
	return exp.After(now)
}

// Get returns the override for key, if present.
func (s *Store) Get(key string) (Override, bool) {
	o, ok := s.Overrides[key]
	return o, ok
}

// Save persists the store to its path atomically (write-temp-then-rename,
// 0600). Used by `penrush init` to materialize an empty store on disk and by
// Add after a mutation.
func (s *Store) Save() error { return s.save() }

func (s *Store) save() error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
