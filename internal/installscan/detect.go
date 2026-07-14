package installscan

import (
	"fmt"
	"sort"
	"strings"
)

// Level is the severity of an install-hook finding.
type Level int

const (
	// LevelNone: no install-lifecycle hook present. Gate 8 passes silently.
	LevelNone Level = iota
	// LevelNA: the ecosystem has no install-script mechanism (Go modules).
	// Never blocks (FR-106 no-false-block EARS).
	LevelNA
	// LevelMedium: an install-lifecycle hook is present, but no fetch+exec
	// pattern was found. Advisory only — does NOT block on this gate
	// (Gate 1 age still applies independently).
	LevelMedium
	// LevelHigh: a network-fetch sink co-occurs with an exec sink inside a
	// hook — the remote-code-on-install pattern. Blocks.
	LevelHigh
	// LevelFailClosed: an install hook the scanner cannot fully resolve
	// (exec of decoded/indirected content). Blocks — mirrors the
	// unparseable-install principle (architecture §A.5).
	LevelFailClosed
)

// Blocks reports whether a finding at this level blocks the install.
func (l Level) Blocks() bool { return l == LevelHigh || l == LevelFailClosed }

// Codes are the stable machine-readable finding identifiers (verdict Reason
// prefixes; user-facing strings and audit rows key on these).
const (
	CodeRemoteCodeOnInstall  = "remote-code-on-install"
	CodeInstallScriptPresent = "install-script-present"
	CodeUnparseableScript    = "unparseable-install-script"
	CodeNA                   = "n/a"
)

// Finding is one Gate-8 static-scan result for one artifact.
type Finding struct {
	Level    Level
	Code     string // one of the Code* constants ("" when LevelNone)
	Detail   string // human-readable explanation (safe to print; no secrets)
	HookPath string // the offending hook file/script path, when applicable
}

// HookFile is one located install-lifecycle hook: a path label plus its raw
// bytes/text. Content is UNTRUSTED attacker-authored data and is only ever read
// (never executed) — the no-execution invariant (delta §V4.9).
type HookFile struct {
	Path    string
	Content string
}

// Detect runs the fetch-sink ∧ exec-sink co-occurrence scan over the located
// hooks for one ecosystem and returns the single most-severe finding.
//
// Precedence: HIGH (explicit fetch+exec) > FAIL-CLOSED (exec of indirected
// content) > MEDIUM (hook present) > NONE. Both HIGH and FAIL-CLOSED block;
// HIGH is preferred when present because its message is more actionable.
//
// It NEVER executes any hook (delta §V4.9). It is deterministic and side-effect
// free — pure text analysis.
func Detect(eco string, hooks []HookFile) Finding {
	if eco == "go" {
		// Go modules have no install-script mechanism. Recorded n/a; never
		// blocks (FR-106 state-driven no-false-block EARS).
		return Finding{Level: LevelNA, Code: CodeNA, Detail: "Go modules have no install-script mechanism"}
	}
	if len(hooks) == 0 {
		return Finding{Level: LevelNone}
	}

	// Deterministic order so the reported HookPath is stable across runs.
	ordered := append([]HookFile(nil), hooks...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })

	best := Finding{Level: LevelMedium, Code: CodeInstallScriptPresent,
		Detail:   "an install-lifecycle hook is present (no fetch+exec pattern detected)",
		HookPath: ordered[0].Path}

	for _, h := range ordered {
		s := h.Content
		fetch := hasFetchSink(s)
		exec := hasExecSink(s)
		switch {
		case fetch && exec:
			// The unambiguous remote-code-on-install pattern — highest severity,
			// return immediately.
			return Finding{
				Level:    LevelHigh,
				Code:     CodeRemoteCodeOnInstall,
				Detail:   fmt.Sprintf("hook %q fetches remote content and executes it (fetch-sink ∧ exec-sink) — remote code at install time", h.Path),
				HookPath: h.Path,
			}
		case exec && hasObfuscation(s) && best.Level < LevelFailClosed:
			// Exec of decoded/indirected content: the fetch is hidden behind
			// indirection and cannot be positively resolved → fail closed.
			best = Finding{
				Level:    LevelFailClosed,
				Code:     CodeUnparseableScript,
				Detail:   fmt.Sprintf("hook %q executes indirected/decoded content the scanner cannot fully resolve — fail-closed (unparseable install script)", h.Path),
				HookPath: h.Path,
			}
		}
	}
	return best
}

// Message renders the finding as the user-facing one-line gate message
// (the FR-106 acceptance-criteria wording). Safe to print — carries no secret.
func (f Finding) Message(eco, name string) string {
	switch f.Level {
	case LevelHigh:
		return fmt.Sprintf("[PenRUSH] '%s' executes remote code at install time (%s) — HIGH", name, shortHook(f.HookPath))
	case LevelFailClosed:
		return fmt.Sprintf("[PenRUSH] '%s' has an install script the scanner cannot fully resolve — fail-closed (unparseable install script)", name)
	case LevelMedium:
		return fmt.Sprintf("[PenRUSH] '%s' declares an install-lifecycle hook (install-script-present) — MEDIUM advisory (does not block on Gate 8)", name)
	case LevelNA:
		return fmt.Sprintf("[PenRUSH] '%s' (%s): G8 n/a — no install-script mechanism", name, eco)
	default:
		return fmt.Sprintf("[PenRUSH] '%s' (%s): no install-lifecycle hook found", name, eco)
	}
}

func shortHook(p string) string {
	if p == "" {
		return "install hook"
	}
	if i := strings.LastIndex(p, "/"); i >= 0 && i < len(p)-1 {
		return p[i+1:]
	}
	return p
}
