package cli

// `penrush audit verify` — the named tamper-evidence control (architecture §B.2
// and STRIDE §C.2 row 3: "penrush audit verify re-walks the chain"). Before
// this command existed, Verify() was only a stats footer line and an init-time
// WARN, and BOTH returned exit 0 even on a BROKEN chain — so no cron/CI/monitor
// could detect tampering by exit status (INT-05). This restores the named
// control and makes detection actionable: a clean chain exits 0; a tampered
// chain exits ExitTamper (3), distinct from a gate block (1) or usage error
// (2). `--json` emits a machine-readable result for monitoring.

import (
	"encoding/json"
	"fmt"

	"github.com/penrush/penrush/internal/audit"
	"github.com/penrush/penrush/internal/penrushdir"
)

// runAudit dispatches `audit` subcommands. The only subcommand is `verify`.
func runAudit(e *Env, args []string) int {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(e.Stderr, "penrush audit: expected a subcommand (verify)\n\nUsage: penrush audit verify [--json]")
		return ExitUsageErr
	}
	return runAuditVerify(e, args[1:])
}

// auditVerifyJSON is the machine-readable result for `--json`.
type auditVerifyJSON struct {
	OK       bool   `json:"ok"`
	Entries  int    `json:"entries"`
	BadSeq   int64  `json:"bad_seq,omitempty"`
	BadField string `json:"bad_field,omitempty"`
	Path     string `json:"path"`
}

func runAuditVerify(e *Env, args []string) int {
	asJSON := false
	for _, a := range args {
		switch a {
		case "--json", "-json":
			asJSON = true
		default:
			fmt.Fprintf(e.Stderr, "penrush audit verify: unknown flag %q (only --json)\n", a)
			return ExitUsageErr
		}
	}

	home, err := e.resolveHome()
	if err != nil {
		fmt.Fprintf(e.Stderr, "penrush audit verify: cannot resolve PenRUSH home: %v\n", err)
		return ExitUsageErr
	}
	path := penrushdir.AuditPath(home)
	vr, verr := audit.Open(path).Verify()
	if verr != nil {
		// An I/O error reading the log is itself a reason not to trust it: treat
		// as a usage/environment error (NOT a clean pass).
		if asJSON {
			_ = json.NewEncoder(e.Stdout).Encode(auditVerifyJSON{OK: false, Path: path})
		} else {
			fmt.Fprintf(e.Stderr, "penrush audit verify: cannot read audit log (%v)\n", verr)
		}
		return ExitUsageErr
	}

	if asJSON {
		out := auditVerifyJSON{OK: vr.OK, Entries: vr.Entries, Path: path}
		if !vr.OK {
			out.BadSeq, out.BadField = vr.BadSeq, vr.BadField
		}
		_ = json.NewEncoder(e.Stdout).Encode(out)
		if vr.OK {
			return ExitPass
		}
		return ExitTamper
	}

	if vr.OK {
		fmt.Fprintf(e.Stdout, "%s audit chain OK — %d entries verified\n", e.accent("[penrush] audit verify"), vr.Entries)
		fmt.Fprintf(e.Stdout, "  path: %s\n", path)
		return ExitPass
	}
	fmt.Fprintf(e.Stderr, "%s audit chain %s at seq %d (field: %s)\n",
		e.accent("[penrush] audit verify"), e.accent("TAMPERED"), vr.BadSeq, vr.BadField)
	fmt.Fprintf(e.Stderr, "  path: %s\n", path)
	fmt.Fprintf(e.Stderr, "  the log has been edited, reordered, or truncated since it was written — investigate before trusting it.\n")
	return ExitTamper
}
