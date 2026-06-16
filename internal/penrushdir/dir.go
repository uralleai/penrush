// Package penrushdir resolves the PenRUSH home directory (~/.penrush by
// default, overridable via PENRUSH_HOME for tests and non-standard setups).
//
// Architecture ref: knowledge/cto/architecture/penrush-phase-0.5.md SB
// (all local state lives under ~/.penrush/; naming ratified SL-3).
package penrushdir

import (
	"os"
	"path/filepath"
)

// EnvHome is the environment variable that overrides the default home.
const EnvHome = "PENRUSH_HOME"

// Home returns the PenRUSH state directory. It does NOT create it.
func Home() (string, error) {
	if v := os.Getenv(EnvHome); v != "" {
		return v, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".penrush"), nil
}

// Ensure creates the home directory tree (home + cache/) with 0700 perms
// and returns the home path.
func Ensure() (string, error) {
	home, err := Home()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(home, "cache"), 0o700); err != nil {
		return "", err
	}
	return home, nil
}

// ConfigPath returns the path of config.json under home.
func ConfigPath(home string) string { return filepath.Join(home, "config.json") }

// OverridesPath returns the path of overrides.json under home.
func OverridesPath(home string) string { return filepath.Join(home, "overrides.json") }

// AuditPath returns the path of audit.jsonl under home.
func AuditPath(home string) string { return filepath.Join(home, "audit.jsonl") }

// MetricsPath returns the path of metrics.json under home.
func MetricsPath(home string) string { return filepath.Join(home, "metrics.json") }

// CacheDir returns the registry-cache directory under home.
func CacheDir(home string) string { return filepath.Join(home, "cache") }
