package cli

// Claude Code PreToolUse hook adapter (architecture §A.4, §C.6, §F).
//
// `penrush hook claude-code` reads a PreToolUse payload on stdin, runs the
// SAME gate the `check` subcommand runs, and emits a structured
// permissionDecision so Claude Code can render allow / deny / ask.
//
// HOOK CONTRACT (fact-checked 2026-06-16 against the official hooks reference
// https://code.claude.com/docs/en/hooks, cross-confirmed via WebSearch of
// code.claude.com/docs/en/hooks-guide):
//
//   - stdin JSON: {"hook_event_name":"PreToolUse","tool_name":"Bash",
//     "tool_input":{"command":"..."}} (plus session_id/cwd/permission_mode we
//     ignore).
//   - Exit 0 → Claude Code parses stdout for hookSpecificOutput JSON.
//     permissionDecision ∈ {"allow","deny","ask","defer"}; "deny" blocks and
//     feeds permissionDecisionReason back to Claude; "allow" skips the prompt;
//     "ask" surfaces the normal permission prompt (our override UX). Multi-hook
//     precedence is deny > defer > ask > allow.
//   - Exit 2 → BLOCK. stdout/JSON ignored; stderr is fed back to Claude. This
//     is the compatibility fallback and the GUARANTEED block path.
//   - ANY OTHER exit code (1, 3, …) → NON-BLOCKING; the tool call PROCEEDS.
//     This is the crashing-gate-bypass risk (§C.6): a gate that crashes with a
//     non-2 code becomes a silent bypass primitive. Therefore every failure
//     path here exits 0-with-deny or 2 — NEVER 1.
//
// PRIMARY path: exit 0 + permissionDecision JSON (supports "ask", the override
// UX). FALLBACK: exit 2 when JSON cannot be emitted or on a fail-closed
// internal error. PANIC: recovered → block (exit 2), honoring
// on_internal_error.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/penrush/penrush/internal/audit"
	"github.com/penrush/penrush/internal/cache"
	"github.com/penrush/penrush/internal/config"
	"github.com/penrush/penrush/internal/gate"
	"github.com/penrush/penrush/internal/override"
	"github.com/penrush/penrush/internal/penrushdir"
)

// ExitHookBlock is the GUARANTEED block exit code for the PreToolUse hook.
// Per the hooks contract ONLY exit 2 reliably blocks the tool call; exit 1 is
// non-blocking (the tool would proceed). The hook adapter therefore never
// returns ExitBlock (=1) — it returns this for the fail-closed fallback path.
const ExitHookBlock = 2

// permissionDecision values (hooks reference).
const (
	decisionAllow = "allow"
	decisionDeny  = "deny"
	decisionAsk   = "ask"
)

// hookPayload is the subset of the PreToolUse stdin JSON we read.
type hookPayload struct {
	HookEventName string `json:"hook_event_name"`
	ToolName      string `json:"tool_name"`
	ToolInput     struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

// hookOutput is the exit-0 structured response.
type hookOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// Stdin is the injectable stdin reader. main.go wires it to os.Stdin; tests
// supply a bytes.Reader. When nil, the hook reads nothing (treated as a parse
// failure → fail-closed).
//
// (Declared as a field on Env via a small accessor so the rest of the package
// keeps the existing Env shape; see env_stdin.go.)

// runHook dispatches `penrush hook <surface>`. The only surface in this build
// is `claude-code`.
func runHook(e *Env, args []string) int {
	if len(args) == 0 || args[0] != "claude-code" {
		fmt.Fprintln(e.Stderr, "penrush hook: expected a surface (claude-code)\n\nUsage: penrush hook claude-code  (reads a PreToolUse JSON payload on stdin)")
		return ExitUsageErr
	}
	return runHookClaudeCode(e)
}

// runHookClaudeCode is the PreToolUse adapter. It NEVER returns ExitBlock (=1);
// every block is either exit 0 + deny JSON (primary) or exit 2 (fallback).
//
// The whole body runs under a panic-recovery layer that converts any internal
// failure into an explicit block (§C.6) — a crashing gate must not become a
// bypass.
func runHookClaudeCode(e *Env) (code int) {
	// on_internal_error fail mode is read inside; default before config loads is
	// "block" (the safe posture, §L-4).
	failMode := "block"

	defer func() {
		if r := recover(); r != nil {
			// A panic anywhere in the hook path. Honor on_internal_error.
			if failMode == "allow" {
				code = emitDecision(e, decisionAllow, fmt.Sprintf("penrush internal error (configured fail-open): %v", r))
				return
			}
			// Block. Prefer the structured deny on exit 0; if even that write
			// fails, exit 2 (the guaranteed block).
			code = failClosed(e, fmt.Sprintf("penrush internal error (fail-closed): %v", r))
		}
	}()

	// 1. Read + parse stdin. A malformed/empty payload is fail-closed: the
	//    reference Python hook fails OPEN here, but for the PRODUCT an
	//    unparseable hook input must not become a silent pass (§C.6 divergence).
	raw, rerr := readStdin(e)
	if rerr != nil || len(raw) == 0 {
		return failClosed(e, "could not read the PreToolUse payload on stdin — fail-closed.")
	}
	var p hookPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return failClosed(e, fmt.Sprintf("unparseable PreToolUse JSON on stdin (%v) — fail-closed.", err))
	}

	// 2. Triage: only Bash tool calls are gated. Anything else → allow (no
	//    opinion). An empty command → allow (nothing to install).
	if p.ToolName != "Bash" {
		return emitDecision(e, decisionAllow, "")
	}
	cmd := p.ToolInput.Command
	if cmd == "" {
		return emitDecision(e, decisionAllow, "")
	}

	// 3. Parse the command (§A.5).
	pr := ParseInstallCommand(cmd)
	switch pr.Action {
	case ActionIgnore:
		// Not an install-like command: allow, no registry call (the <30ms p95
		// no-match short-circuit, §J).
		return emitDecision(e, decisionAllow, "")
	case ActionAllow:
		return emitDecision(e, decisionAllow, pr.Reason)
	case ActionBlock:
		// Structural block (missing pin / system pkg / go @latest / unparseable):
		// deny via the structured path, with the override hint when we have a key.
		return emitDeny(e, structuralDenyReason(pr))
	case ActionGate:
		// fallthrough below
	default:
		return failClosed(e, "internal: unknown parse action — fail-closed.")
	}

	// 4. ActionGate: run the SAME gate engine the `check` path runs. Identical
	//    inputs → identical Verdict → parity by construction.
	home, herr := e.resolveHomeEnsured()
	if herr != nil {
		return failClosed(e, fmt.Sprintf("cannot open PenRUSH home (%v) — fail-closed. Run `penrush init`.", herr))
	}

	cfg, cerr := config.Load(penrushdir.ConfigPath(home))
	if cerr != nil {
		def, derr := config.Default()
		if derr != nil {
			return failClosed(e, fmt.Sprintf("config unavailable and default generation failed (%v) — fail-closed.", derr))
		}
		cfg = def
	}
	failMode = cfg.OnInternalError // now the recover() honors the configured mode

	overrides, oerr := override.Load(penrushdir.OverridesPath(home))
	if oerr != nil {
		return failClosed(e, fmt.Sprintf("override store unreadable (%v) — fail-closed (a bypass primitive must not be trusted when corrupt).", oerr))
	}

	var c *cache.Cache
	if ca, kerr := cache.New(penrushdir.CacheDir(home), cfg.CacheHMACKey); kerr == nil {
		c = ca
	}

	eng := &gate.Engine{
		Config:    cfg,
		Overrides: overrides,
		Cache:     c,
		Resolvers: e.resolvers(cfg),
		Now:       e.Now,
	}

	v := eng.CheckGate1(context.Background(), pr.Eco, pr.Name, pr.Version)

	// 5. Audit the decision (same entry shape as `check`). An audit-write
	//    failure is itself fail-closed: if we cannot record a decision we do not
	//    silently allow.
	entry := verdictToAudit(pr.Eco, pr.Name, pr.Version, v)
	entry.Command = cmd // the real shell command (redacted by the audit writer)
	entry.Actor = "claude-code-hook"
	if _, aerr := audit.Open(penrushdir.AuditPath(home)).Append(entry); aerr != nil {
		return failClosed(e, fmt.Sprintf("could not write audit entry (%v) — fail-closed.", aerr))
	}

	// 6. Map the verdict onto a permissionDecision and emit (exit 0 + JSON).
	switch v.Decision {
	case gate.Pass, gate.OverrideUsed:
		return emitDecision(e, decisionAllow, v.Reason)
	default:
		return emitDeny(e, v.Reason)
	}
}

// structuralDenyReason adds the override path to a structural block reason when
// an override key is known. For the structural blocks that are policy
// (system-pkg, missing-pin), there is no single artifact key, so the reason
// stands alone.
func structuralDenyReason(pr ParseResult) string {
	if pr.OverrideKey != "" {
		return pr.Reason + " Override: penrush override add " + pr.OverrideKey + " --reason \"...\""
	}
	return pr.Reason
}

// emitDecision writes a permissionDecision JSON to stdout and returns exit 0.
// allow/ask ride this path. deny is emitted via emitDeny (which falls back to
// exit 2 if the JSON write fails — a denial that can't be written must still
// block).
func emitDecision(e *Env, decision, reason string) int {
	out := hookOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       decision,
		PermissionDecisionReason: reason,
	}}
	b, err := json.Marshal(out)
	if err != nil {
		// Should be impossible for these plain-string fields, but be safe: an
		// allow whose JSON fails just exits 0 (the tool proceeds — allow was the
		// intent); a deny is handled in emitDeny with an exit-2 fallback.
		if decision == decisionDeny {
			return failClosed(e, reason)
		}
		return ExitPass
	}
	fmt.Fprintln(e.Stdout, string(b))
	return ExitPass
}

// emitDeny writes a deny decision. If the structured JSON cannot be written for
// any reason, it falls back to exit 2 (the guaranteed block) — a denial is
// never allowed to degrade into a non-blocking exit.
func emitDeny(e *Env, reason string) int {
	out := hookOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       decisionDeny,
		PermissionDecisionReason: reason,
	}}
	b, err := json.Marshal(out)
	if err != nil {
		return failClosed(e, reason)
	}
	fmt.Fprintln(e.Stdout, string(b))
	return ExitPass // exit 0 + deny JSON blocks the tool call
}

// failClosed is the GUARANTEED block fallback: stderr message + exit 2. Used
// when we cannot (or should not) emit structured JSON — a malformed payload, an
// internal error under on_internal_error=block, or a JSON-encode failure on a
// denial. Exit 2 is the ONLY code that reliably blocks (exit 1 would let the
// tool proceed — the crashing-gate-bypass, §C.6).
func failClosed(e *Env, reason string) int {
	fmt.Fprintf(e.Stderr, "%s %s\n", e.accent("[penrush] BLOCK"), reason)
	return ExitHookBlock
}

// readStdin reads the whole stdin payload via the Env's injectable reader.
func readStdin(e *Env) ([]byte, error) {
	r := e.stdin()
	if r == nil {
		return nil, fmt.Errorf("no stdin reader")
	}
	// Cap the read: a PreToolUse command payload is small; 1 MiB is a generous
	// ceiling that prevents a pathological stdin from exhausting memory.
	return io.ReadAll(io.LimitReader(r, 1<<20))
}
