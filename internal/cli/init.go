package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/penrush/penrush/internal/audit"
	"github.com/penrush/penrush/internal/config"
	"github.com/penrush/penrush/internal/override"
	"github.com/penrush/penrush/internal/penrushdir"
)

// runInit creates ~/.penrush/ and its initial artifacts. It is idempotent:
// re-running it preserves an existing config (and its per-install cache HMAC
// key) and an existing override store; it never truncates the audit log.
//
// Defaults written (per architecture §B.4 + §L-4):
//   - config.json   : cooldown_days.default=14, on_internal_error="block",
//     telemetry="off", a fresh random cache_hmac_key
//   - overrides.json : empty store (schema_version=1)
//   - audit.jsonl    : created empty (chain genesis is implicit; the first
//     Append chains from GenesisHash)
func runInit(e *Env, args []string) int {
	if len(args) > 0 {
		fmt.Fprintf(e.Stderr, "penrush init: takes no arguments, got %v\n", args)
		return ExitUsageErr
	}

	home, err := e.resolveHomeEnsured()
	if err != nil {
		fmt.Fprintf(e.Stderr, "penrush init: cannot create home dir: %v\n", err)
		return ExitUsageErr
	}

	// 1. config.json — preserve an existing one (keeps the cache HMAC key
	//    stable so previously-cached entries stay valid).
	cfgPath := penrushdir.ConfigPath(home)
	createdConfig := false
	if _, err := config.Load(cfgPath); errors.Is(err, os.ErrNotExist) {
		cfg, derr := config.Default()
		if derr != nil {
			fmt.Fprintf(e.Stderr, "penrush init: generating default config: %v\n", derr)
			return ExitUsageErr
		}
		if serr := cfg.Save(cfgPath); serr != nil {
			fmt.Fprintf(e.Stderr, "penrush init: writing config: %v\n", serr)
			return ExitUsageErr
		}
		createdConfig = true
	} else if err != nil {
		fmt.Fprintf(e.Stderr, "penrush init: existing config is unreadable (%v) — refusing to overwrite; fix or remove %s\n", err, cfgPath)
		return ExitUsageErr
	}

	// 2. overrides.json — Load initializes an empty in-memory store on a
	//    missing file; Save persists it so the empty file exists on disk
	//    (authoritative schema, not a hand-rolled literal).
	ovPath := penrushdir.OverridesPath(home)
	createdOverrides := false
	if _, err := os.Stat(ovPath); errors.Is(err, os.ErrNotExist) {
		store, lerr := override.Load(ovPath)
		if lerr != nil {
			fmt.Fprintf(e.Stderr, "penrush init: preparing override store: %v\n", lerr)
			return ExitUsageErr
		}
		if werr := store.Save(); werr != nil {
			fmt.Fprintf(e.Stderr, "penrush init: writing override store: %v\n", werr)
			return ExitUsageErr
		}
		createdOverrides = true
	}

	// 3. audit.jsonl — create empty if absent (lazy chain; first Append chains
	//    from genesis). Never truncate an existing log.
	auditPath := penrushdir.AuditPath(home)
	createdAudit := false
	if _, err := os.Stat(auditPath); errors.Is(err, os.ErrNotExist) {
		f, ferr := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY, 0o600)
		if ferr != nil {
			fmt.Fprintf(e.Stderr, "penrush init: creating audit log: %v\n", ferr)
			return ExitUsageErr
		}
		_ = f.Close()
		createdAudit = true
	}
	// Sanity: a present log must still verify (a corrupt log is surfaced now,
	// not silently at first check).
	if vr, verr := audit.Open(auditPath).Verify(); verr == nil && !vr.OK {
		fmt.Fprintf(e.Stderr, "%s existing audit log fails verification at seq %d (%s) — investigate %s before relying on it\n",
			e.accent("[penrush] WARN"), vr.BadSeq, vr.BadField, auditPath)
	}

	fmt.Fprintf(e.Stdout, "%s PenRUSH home ready at %s\n", e.accent("[penrush]"), home)
	fmt.Fprintf(e.Stdout, "  config.json    %s\n", state(createdConfig))
	fmt.Fprintf(e.Stdout, "  overrides.json %s\n", state(createdOverrides))
	fmt.Fprintf(e.Stdout, "  audit.jsonl    %s\n", state(createdAudit))
	fmt.Fprintf(e.Stdout, "  cache/         ready\n")
	fmt.Fprintf(e.Stdout, "\nDefaults: %d-day cool-down, on_internal_error=block, telemetry=off.\n",
		config.DefaultCooldownDays)
	fmt.Fprintf(e.Stdout, "Next: %s\n", e.bold("penrush check npm left-pad@1.3.0"))
	return ExitPass
}

func state(created bool) string {
	if created {
		return "created"
	}
	return "already present (kept)"
}

// resolveHomeEnsured returns the PenRUSH home, creating the tree. When e.Home
// is set (tests), it is used directly and created with the cache subdir.
func (e *Env) resolveHomeEnsured() (string, error) {
	if e.Home != "" {
		if err := os.MkdirAll(penrushdir.CacheDir(e.Home), 0o700); err != nil {
			return "", err
		}
		return e.Home, nil
	}
	return penrushdir.Ensure()
}

// resolveHome returns the home without creating it (read paths). Tests set
// e.Home; production resolves via penrushdir.
func (e *Env) resolveHome() (string, error) {
	if e.Home != "" {
		return e.Home, nil
	}
	return penrushdir.Home()
}
