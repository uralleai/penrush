package cli

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/penrush/penrush/internal/audit"
	"github.com/penrush/penrush/internal/override"
	"github.com/penrush/penrush/internal/penrushdir"
)

// runOverride dispatches `override` subcommands. Chunk 1 ships `add` (FR-004).
func runOverride(e *Env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(e.Stderr, "penrush override: expected a subcommand (add)\n\nUsage: penrush override add <ecosystem>:<artifact> --reason \"...\" [--ttl-days N]")
		return ExitUsageErr
	}
	switch args[0] {
	case "add":
		return runOverrideAdd(e, args[1:])
	default:
		fmt.Fprintf(e.Stderr, "penrush override: unknown subcommand %q (have: add)\n", args[0])
		return ExitUsageErr
	}
}

// runOverrideAdd appends an override to ~/.penrush/overrides.json (FR-004).
// Reason is mandatory; default TTL 30 days, clamped to the 30-day max (SC.4).
// The action is itself audited (decision=override_added) so the audit log is
// a complete history of policy mutations, not just install decisions.
func runOverrideAdd(e *Env, args []string) int {
	// Separate the single positional key from the flags BEFORE parsing. Go's
	// stdlib flag stops at the first non-flag token, so `override add npm:foo
	// --reason "x"` would otherwise mis-parse. Extracting the key first makes
	// the command order-independent (key may precede or follow the flags).
	key, flagArgs, perr := splitKeyAndFlags(args)
	if perr != nil {
		fmt.Fprintf(e.Stderr, "penrush override add: %v\n", perr)
		return ExitUsageErr
	}

	fs := flag.NewFlagSet("override add", flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	reason := fs.String("reason", "", "mandatory justification for the override (FR-004)")
	ttlDays := fs.Int("ttl-days", 0, "override lifetime in days (default 30, max 30)")
	if err := fs.Parse(flagArgs); err != nil {
		return ExitUsageErr
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintf(e.Stderr, "penrush override add: unexpected extra arguments %v (expected one key <ecosystem>:<artifact> plus flags)\n", fs.Args())
		return ExitUsageErr
	}

	if strings.TrimSpace(*reason) == "" {
		fmt.Fprintf(e.Stderr, "penrush override add: --reason is mandatory (FR-004). An override without a recorded reason is exactly the ceremonial-gate failure PenRUSH exists to prevent.\n")
		return ExitUsageErr
	}
	if err := override.ValidateKey(key); err != nil {
		fmt.Fprintf(e.Stderr, "penrush override add: %v\n", err)
		return ExitUsageErr
	}

	home, err := e.resolveHomeEnsured()
	if err != nil {
		fmt.Fprintf(e.Stderr, "penrush override add: cannot open PenRUSH home: %v\n", err)
		return ExitUsageErr
	}
	store, err := override.Load(penrushdir.OverridesPath(home))
	if err != nil {
		fmt.Fprintf(e.Stderr, "penrush override add: override store unreadable (%v) — refusing to write over a corrupt store.\n", err)
		return ExitUsageErr
	}

	ttl := time.Duration(*ttlDays) * 24 * time.Hour
	o, err := store.Add(key, *reason, ttl, e.now())
	if err != nil {
		fmt.Fprintf(e.Stderr, "penrush override add: %v\n", err)
		return ExitUsageErr
	}

	// Audit the policy mutation (best-effort; a failed audit here does not
	// undo the stored override, but we surface it loudly).
	cmd := fmt.Sprintf("penrush override add %s --reason %q", key, *reason)
	entry := audit.Entry{
		Command:      cmd,
		Decision:     audit.DecisionOverrideAdded,
		GatesRun:     []string{},
		GatesPassed:  []string{},
		GatesFailed:  []string{},
		Reason:       *reason,
		Actor:        "cli",
		PolicySource: "local",
		OverrideKey:  key,
	}
	if _, aerr := audit.Open(penrushdir.AuditPath(home)).Append(entry); aerr != nil {
		fmt.Fprintf(e.Stderr, "%s override stored but audit write failed: %v\n", e.accent("[penrush] WARN"), aerr)
	}

	fmt.Fprintf(e.Stdout, "%s override added for %s\n", e.accent("[penrush]"), e.bold(key))
	fmt.Fprintf(e.Stdout, "  reason:  %s\n", o.Reason)
	fmt.Fprintf(e.Stdout, "  expires: %s (UTC) — %d-day window\n", o.ExpiresAt, daysFromTTL(ttl))
	fmt.Fprintf(e.Stdout, "  scope:   %s\n", o.Scope)
	return ExitPass
}

func daysFromTTL(ttl time.Duration) int {
	if ttl <= 0 || ttl > override.MaxTTL {
		return int(override.DefaultTTL.Hours() / 24)
	}
	return int(ttl.Hours() / 24)
}

// valueFlags are the override-add flags that consume a following argument when
// written in space form (--reason X). The "--flag=value" form is self-
// contained and needs no lookahead.
var valueFlags = map[string]bool{
	"-reason": true, "--reason": true,
	"-ttl-days": true, "--ttl-days": true,
}

// splitKeyAndFlags pulls exactly one positional key out of args (in any
// position) and returns the remaining tokens as a flag-only slice for
// flag.Parse. It returns an error if zero or more than one positional is
// present. This makes `override add` order-independent.
func splitKeyAndFlags(args []string) (key string, flagArgs []string, err error) {
	var positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "-"):
			flagArgs = append(flagArgs, a)
			// If it's a space-form value flag (no '='), the next token is its
			// value, not a positional.
			if !strings.Contains(a, "=") && valueFlags[a] && i+1 < len(args) {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
		default:
			positionals = append(positionals, a)
		}
	}
	switch len(positionals) {
	case 0:
		return "", nil, fmt.Errorf("missing key <ecosystem>:<artifact>")
	case 1:
		return positionals[0], flagArgs, nil
	default:
		return "", nil, fmt.Errorf("expected exactly one key <ecosystem>:<artifact>, got %d (%v)", len(positionals), positionals)
	}
}
