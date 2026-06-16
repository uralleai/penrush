// Package cache implements the registry-response cache (~/.penrush/cache/),
// one JSON file per key, with HMAC integrity per SB.3.
//
// TTL policy (SB.3, binding):
//   - PASS verdict (age >= cooldown): 30 days — a published timestamp only
//     gets older; passing artifacts cannot regress to failing on age.
//   - BLOCK verdict (age < cooldown): until the cooldown-clear date EXACTLY —
//     self-expiring block; re-check happens precisely when the artifact
//     could first pass.
//   - Unverifiable (registry error): NEVER cached — fail-closed must be
//     re-evaluated live every time (FR-003).
//
// Integrity: entries carry an HMAC-SHA256 tied to a per-install random key
// in config.json. A poisoned cache entry is a gate bypass (SC.3 #3), so an
// entry with a bad MAC is treated as a miss. Same honest local-attacker
// limitation as the audit chain (SB.2).
package cache

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SchemaVersion of cache entries.
const SchemaVersion = 1

// PassTTL is the cache lifetime of a passing age verdict.
const PassTTL = 30 * 24 * time.Hour

// Entry is one cached registry verdict.
type Entry struct {
	SchemaVersion int    `json:"schema_version"`
	Key           string `json:"key"`          // e.g. "npm:left-pad@1.3.0"
	Verdict       string `json:"verdict"`      // "pass" | "block"
	PublishedAt   string `json:"published_at"` // RFC3339
	FetchedAt     string `json:"fetched_at"`   // RFC3339
	ExpiresAt     string `json:"expires_at"`   // RFC3339
	SourceURL     string `json:"source_url"`
	MAC           string `json:"mac"` // hex HMAC-SHA256 over canonical content
}

// Cache is a directory-backed store.
type Cache struct {
	dir string
	key []byte // HMAC key
}

// New returns a cache rooted at dir using hmacKeyHex from config.
func New(dir, hmacKeyHex string) (*Cache, error) {
	key, err := hex.DecodeString(hmacKeyHex)
	if err != nil || len(key) == 0 {
		return nil, errors.New("cache: invalid HMAC key")
	}
	return &Cache{dir: dir, key: key}, nil
}

// filename maps a cache key to a safe file name.
func (c *Cache) filename(key string) string {
	h := sha256.Sum256([]byte(key))
	return filepath.Join(c.dir, hex.EncodeToString(h[:16])+".json")
}

func (c *Cache) mac(e Entry) string {
	m := hmac.New(sha256.New, c.key)
	fmt.Fprintf(m, "%d|%s|%s|%s|%s|%s|%s",
		e.SchemaVersion, e.Key, e.Verdict, e.PublishedAt, e.FetchedAt, e.ExpiresAt, e.SourceURL)
	return hex.EncodeToString(m.Sum(nil))
}

// Put stores a verdict. Callers must only pass "pass" or "block" — the
// unverifiable case must never be cached (FR-003) and is rejected here.
func (c *Cache) Put(key, verdict string, publishedAt time.Time, sourceURL string, cooldownClear time.Time, now time.Time) error {
	var expires time.Time
	switch verdict {
	case "pass":
		expires = now.Add(PassTTL)
	case "block":
		expires = cooldownClear
	default:
		return fmt.Errorf("cache: refusing to cache verdict %q (only pass/block are cacheable per FR-003)", verdict)
	}
	e := Entry{
		SchemaVersion: SchemaVersion,
		Key:           key,
		Verdict:       verdict,
		PublishedAt:   publishedAt.UTC().Format(time.RFC3339),
		FetchedAt:     now.UTC().Format(time.RFC3339),
		ExpiresAt:     expires.UTC().Format(time.RFC3339),
		SourceURL:     sourceURL,
	}
	e.MAC = c.mac(e)
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	tmp := c.filename(key) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.filename(key))
}

// Get returns a live entry for key, or (nil, false) on miss / expiry /
// integrity failure. Expired and MAC-invalid entries are deleted.
func (c *Cache) Get(key string, now time.Time) (*Entry, bool) {
	raw, err := os.ReadFile(c.filename(key))
	if err != nil {
		return nil, false
	}
	var e Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		_ = os.Remove(c.filename(key))
		return nil, false
	}
	if e.Key != key || !hmac.Equal([]byte(c.mac(e)), []byte(e.MAC)) {
		// Poisoned or foreign entry — treat as miss and drop it (SC.3 #3).
		_ = os.Remove(c.filename(key))
		return nil, false
	}
	exp, err := time.Parse(time.RFC3339, e.ExpiresAt)
	if err != nil || !exp.After(now) {
		_ = os.Remove(c.filename(key))
		return nil, false
	}
	return &e, true
}

// Stats counts entries on disk (for `penrush stats`).
func (c *Cache) Stats() (entries int) {
	matches, _ := filepath.Glob(filepath.Join(c.dir, "*.json"))
	for _, m := range matches {
		if !strings.HasSuffix(m, ".tmp") {
			entries++
		}
	}
	return entries
}
