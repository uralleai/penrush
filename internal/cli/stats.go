package cli

import (
	"fmt"
	"sort"

	"github.com/penrush/penrush/internal/audit"
	"github.com/penrush/penrush/internal/cache"
	"github.com/penrush/penrush/internal/config"
	"github.com/penrush/penrush/internal/penrushdir"
)

// runStats prints a LOCAL-ONLY readout of the audit log. It opens no network
// connection and contacts no registry — it reads ~/.penrush/audit.jsonl and
// counts the cache directory. This satisfies the chunk-1 scope of PMA's
// metrics spec (M-01 gate-checks, M-02 block rate, M-03 override rate are all
// derivable from the local audit log; the consented `stats export --cohort`
// flow with metrics.json is a later chunk and is intentionally NOT here).
//
// Zero-telemetry invariant (architecture §I, NFR-003): there is no send path
// in this command and none in this binary.
func runStats(e *Env, args []string) int {
	if len(args) > 0 {
		fmt.Fprintf(e.Stderr, "penrush stats: takes no arguments in this build, got %v\n", args)
		fmt.Fprintf(e.Stderr, "(the consented `stats export --cohort` flow lands in a later chunk)\n")
		return ExitUsageErr
	}

	home, err := e.resolveHome()
	if err != nil {
		fmt.Fprintf(e.Stderr, "penrush stats: cannot resolve PenRUSH home: %v\n", err)
		return ExitUsageErr
	}

	log := audit.Open(penrushdir.AuditPath(home))
	entries, err := log.ReadAll()
	if err != nil {
		fmt.Fprintf(e.Stderr, "penrush stats: audit log unreadable: %v\n", err)
		return ExitUsageErr
	}

	var (
		checks        int // pass + block + override_used (install-decision events)
		passes        int
		blocks        int
		overridesUsed int
		overridesAdd  int
		internalErr   int
		ecoChecks     = map[string]int{}
	)
	for _, en := range entries {
		switch en.Decision {
		case audit.DecisionPass:
			checks++
			passes++
		case audit.DecisionBlock:
			checks++
			blocks++
		case audit.DecisionOverrideUsed:
			checks++
			overridesUsed++
		case audit.DecisionOverrideAdded:
			overridesAdd++
		case audit.DecisionInternalError:
			checks++
			blocks++
			internalErr++
		}
		if eco := ecosystemOf(en.Command); eco != "" {
			ecoChecks[eco]++
		}
	}

	fmt.Fprintf(e.Stdout, "%s local audit readout (no network)\n", e.accent("[penrush] stats"))
	fmt.Fprintf(e.Stdout, "  home:               %s\n", home)
	fmt.Fprintf(e.Stdout, "  audit entries:      %d\n", len(entries))
	fmt.Fprintf(e.Stdout, "  gate checks:        %d\n", checks)
	fmt.Fprintf(e.Stdout, "  passes:             %d\n", passes)
	fmt.Fprintf(e.Stdout, "  blocks:             %d  (block rate %s)\n", blocks, pct(blocks, checks))
	if internalErr > 0 {
		fmt.Fprintf(e.Stdout, "    of which internal-error blocks: %d\n", internalErr)
	}
	fmt.Fprintf(e.Stdout, "  overrides used:     %d  (override-of-blocks rate %s)\n", overridesUsed, pct(overridesUsed, blocks+overridesUsed))
	fmt.Fprintf(e.Stdout, "  overrides added:    %d\n", overridesAdd)

	if len(ecoChecks) > 0 {
		fmt.Fprintf(e.Stdout, "  by ecosystem:\n")
		for _, kv := range sortedCounts(ecoChecks) {
			fmt.Fprintf(e.Stdout, "    %-8s %d\n", kv.k, kv.v)
		}
	}

	// Cache entry count (best-effort; requires the HMAC key only to construct,
	// not to count files).
	if cfg, cerr := config.Load(penrushdir.ConfigPath(home)); cerr == nil {
		if c, kerr := cache.New(penrushdir.CacheDir(home), cfg.CacheHMACKey); kerr == nil {
			fmt.Fprintf(e.Stdout, "  cache entries:      %d\n", c.Stats())
		}
	}

	// Chain integrity (tamper-evidence surface, NFR-004).
	if vr, verr := log.Verify(); verr == nil {
		if vr.OK {
			fmt.Fprintf(e.Stdout, "  chain integrity:    OK (%d entries verified)\n", vr.Entries)
		} else {
			fmt.Fprintf(e.Stdout, "  chain integrity:    %s at seq %d (field: %s)\n",
				e.accent("BROKEN"), vr.BadSeq, vr.BadField)
		}
	}
	return ExitPass
}

// ecosystemOf extracts the ecosystem token from a "penrush check <eco> ..."
// command string. Returns "" for non-check commands.
func ecosystemOf(command string) string {
	const prefix = "penrush check "
	if len(command) <= len(prefix) || command[:len(prefix)] != prefix {
		return ""
	}
	rest := command[len(prefix):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == ' ' || rest[i] == ':' {
			return rest[:i]
		}
	}
	return rest
}

func pct(num, den int) string {
	if den == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%%", 100*float64(num)/float64(den))
}

type countKV struct {
	k string
	v int
}

func sortedCounts(m map[string]int) []countKV {
	out := make([]countKV, 0, len(m))
	for k, v := range m {
		out = append(out, countKV{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].v != out[j].v {
			return out[i].v > out[j].v
		}
		return out[i].k < out[j].k
	})
	return out
}
