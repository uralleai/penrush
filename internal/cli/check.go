package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/penrush/penrush/internal/audit"
	"github.com/penrush/penrush/internal/cache"
	"github.com/penrush/penrush/internal/config"
	"github.com/penrush/penrush/internal/gate"
	"github.com/penrush/penrush/internal/override"
	"github.com/penrush/penrush/internal/penrushdir"
	"github.com/penrush/penrush/internal/registry"
)

// checkEcosystems in this build. All eight per PRD §5.4 / arch §A.6.
var checkEcosystems = []string{"npm", "pypi", "github", "cargo", "gem", "go", "docker", "mcp"}

// runCheck is the dry-run gate command (FR-007). It runs Gate 1
// (publication-age) against one artifact, prints the verdict, writes one
// audit entry, and returns a fail-closed exit code. It installs nothing.
//
// Accepted forms (the brief's two-arg form AND FR-007's colon form):
//
//	penrush check npm left-pad@1.3.0
//	penrush check npm:left-pad@1.3.0
func runCheck(e *Env, args []string) int {
	eco, name, version, perr := parseCheckArgs(args)
	if perr != nil {
		fmt.Fprintf(e.Stderr, "penrush check: %v\n\nUsage: penrush check <ecosystem> <pkg>[@version]\n  ecosystems: %s\n",
			perr, strings.Join(checkEcosystems, ", "))
		return ExitUsageErr
	}

	home, err := e.resolveHomeEnsured()
	if err != nil {
		// Cannot establish state dir: fail closed (we cannot even audit).
		fmt.Fprintf(e.Stderr, "%s cannot open PenRUSH home (%v) — fail-closed. Run `penrush init`.\n",
			e.accent("[penrush] BLOCK"), err)
		return ExitBlock
	}

	// Load config; a missing/unreadable config falls back to compiled defaults
	// with on_internal_error=block (the safe posture, §C.6/§L-4).
	cfg, cerr := config.Load(penrushdir.ConfigPath(home))
	if cerr != nil {
		def, derr := config.Default()
		if derr != nil {
			fmt.Fprintf(e.Stderr, "%s config unavailable and default generation failed (%v) — fail-closed.\n",
				e.accent("[penrush] BLOCK"), derr)
			return ExitBlock
		}
		cfg = def
	}

	overrides, oerr := override.Load(penrushdir.OverridesPath(home))
	if oerr != nil {
		fmt.Fprintf(e.Stderr, "%s override store unreadable (%v) — fail-closed (a bypass primitive must not be trusted when corrupt).\n",
			e.accent("[penrush] BLOCK"), oerr)
		return e.auditAndExit(home, eco, name, version, gate.Verdict{
			Gate: "G1", Decision: gate.Block,
			Reason: fmt.Sprintf("override store unreadable: %v", oerr),
		}, cfg, true)
	}

	// Cache is best-effort: a bad HMAC key just disables caching, it never
	// blocks a check (the gate still resolves live).
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

	ctx := context.Background()
	v := eng.CheckGate1(ctx, eco, name, version)
	e.printVerdict(eco, name, version, v)
	return e.auditAndExit(home, eco, name, version, v, cfg, false)
}

// resolvers builds the per-ecosystem resolver set for this build. A test may
// fully override it via e.Resolvers; otherwise the HTTP client is injected in
// tests (e.NewClient) or the hardened shared client is used in production.
// registry.Version drives the User-Agent.
func (e *Env) resolvers(cfg *config.Config) map[string]registry.Resolver {
	registry.Version = Version
	if e.Resolvers != nil {
		return e.Resolvers
	}
	var client *registry.Client
	if e.NewClient != nil {
		client = e.NewClient()
	} else {
		client = registry.NewClient()
	}
	return map[string]registry.Resolver{
		// Chunk 1.
		"npm":    &registry.NPM{Client: client},
		"pypi":   &registry.PyPI{Client: client},
		"github": &registry.GitHub{Client: client, TokenEnv: cfg.GithubTokenEnv},
		// Chunk 2 — same hardened client; per-ecosystem rate governors live
		// inside each resolver (cargo 1 rps, gem 10 rps). The seam is unchanged.
		"cargo":  &registry.Cargo{Client: client},
		"gem":    &registry.RubyGems{Client: client},
		"go":     &registry.GoMod{Client: client},
		"docker": &registry.Docker{Client: client},
		"mcp":    &registry.MCP{Client: client},
	}
}

// auditAndExit writes the audit entry for a verdict and returns the exit code.
// Audit-write failure is itself fail-closed: if we cannot record a decision we
// do not silently pass.
func (e *Env) auditAndExit(home, eco, name, version string, v gate.Verdict, cfg *config.Config, alreadyPrinted bool) int {
	entry := verdictToAudit(eco, name, version, v)
	if _, err := audit.Open(penrushdir.AuditPath(home)).Append(entry); err != nil {
		fmt.Fprintf(e.Stderr, "%s could not write audit entry (%v) — fail-closed.\n",
			e.accent("[penrush] BLOCK"), err)
		return ExitBlock
	}
	switch v.Decision {
	case gate.Pass, gate.OverrideUsed:
		return ExitPass
	default:
		return ExitBlock
	}
}

// verdictToAudit maps a gate verdict onto an audit entry. The Command field is
// the (reconstructable) check command; the audit writer redacts it
// unconditionally (FR-011), though a `check` command carries no secret.
func verdictToAudit(eco, name, version string, v gate.Verdict) audit.Entry {
	cmd := fmt.Sprintf("penrush check %s %s", eco, name)
	if version != "" {
		cmd = fmt.Sprintf("penrush check %s %s@%s", eco, name, version)
	}
	dec := audit.DecisionBlock
	var passed, failed []string
	switch v.Decision {
	case gate.Pass:
		dec, passed = audit.DecisionPass, []string{v.Gate}
	case gate.OverrideUsed:
		dec, passed = audit.DecisionOverrideUsed, []string{v.Gate}
	default:
		dec, failed = audit.DecisionBlock, []string{v.Gate}
	}
	return audit.Entry{
		Command:      cmd,
		Decision:     dec,
		GatesRun:     []string{v.Gate},
		GatesPassed:  passed,
		GatesFailed:  failed,
		Reason:       v.Reason,
		Actor:        "cli",
		PolicySource: "local",
		OverrideKey:  overrideKeyFor(v, eco, name),
	}
}

func overrideKeyFor(v gate.Verdict, eco, name string) string {
	if v.Decision == gate.OverrideUsed {
		return gate.ArtifactKey(eco, name)
	}
	return ""
}

// printVerdict renders the human-readable verdict block.
func (e *Env) printVerdict(eco, name, version string, v gate.Verdict) {
	artifact := name
	if version != "" {
		artifact = name + "@" + version
	}
	switch v.Decision {
	case gate.Pass:
		fmt.Fprintf(e.Stdout, "%s %s:%s\n", e.label("PASS", v.Decision), eco, artifact)
	case gate.OverrideUsed:
		fmt.Fprintf(e.Stdout, "%s %s:%s\n", e.label("OVERRIDE", v.Decision), eco, artifact)
	default:
		fmt.Fprintf(e.Stdout, "%s %s:%s\n", e.label("BLOCK", v.Decision), eco, artifact)
	}
	fmt.Fprintf(e.Stdout, "  gate:   %s (publication-age)\n", v.Gate)
	fmt.Fprintf(e.Stdout, "  reason: %s\n", v.Reason)
	if v.AgeDays >= 0 {
		fmt.Fprintf(e.Stdout, "  age:    %.1f days\n", v.AgeDays)
	}
	if v.SourceURL != "" {
		fmt.Fprintf(e.Stdout, "  source: %s (%s%s)\n", v.SourceURL, v.Confidence, cacheSuffix(v.FromCache))
	}
	if !v.ClearAt.IsZero() {
		fmt.Fprintf(e.Stdout, "  clears: %s (UTC)\n", v.ClearAt.UTC().Format("2006-01-02"))
	}
	// Override path on BLOCK (brief requirement). The gate's Reason already
	// embeds it for the failure cases; this is the always-visible footer.
	if v.Decision == gate.Block {
		fmt.Fprintf(e.Stdout, "  to allow anyway: %s\n",
			e.bold(fmt.Sprintf("penrush override add %s --reason \"...\"", gate.ArtifactKey(eco, name))))
	}
}

func cacheSuffix(fromCache bool) string {
	if fromCache {
		return ", cached"
	}
	return ""
}

// label renders the decision tag with optional amber accent (PASS/OVERRIDE
// plain; BLOCK gets the signal-amber accent).
func (e *Env) label(text string, d gate.Decision) string {
	tag := "[penrush] " + text
	if d == gate.Block {
		return e.accent(tag)
	}
	return tag
}

// parseCheckArgs accepts both `eco pkg[@version]` and `eco:pkg[@version]`.
func parseCheckArgs(args []string) (eco, name, version string, err error) {
	// Strip a leading flagless token; we accept no flags on check in chunk 1.
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			return "", "", "", fmt.Errorf("unknown flag %q (check takes no flags in this build)", a)
		}
	}
	switch len(args) {
	case 1:
		// colon form: eco:name[@version]
		ec, rest, ok := strings.Cut(args[0], ":")
		if !ok || ec == "" || rest == "" {
			return "", "", "", fmt.Errorf("expected <ecosystem> <pkg> or <ecosystem>:<pkg>, got %q", args[0])
		}
		eco = ec
		name, version = splitVersion(rest)
	case 2:
		eco = args[0]
		name, version = splitVersion(args[1])
	default:
		return "", "", "", fmt.Errorf("expected exactly <ecosystem> <pkg>[@version], got %d argument(s)", len(args))
	}
	eco = strings.ToLower(strings.TrimSpace(eco))
	if !isKnownEcosystem(eco) {
		return "", "", "", fmt.Errorf("ecosystem %q not in this build (have: %s)", eco, strings.Join(checkEcosystems, ", "))
	}
	if strings.TrimSpace(name) == "" {
		return "", "", "", fmt.Errorf("empty package name")
	}
	return eco, name, version, nil
}

// splitVersion splits "name@version" on the LAST '@' so scoped npm names
// (@scope/pkg@1.2.3) split correctly into (@scope/pkg, 1.2.3).
func splitVersion(s string) (name, version string) {
	if i := strings.LastIndex(s, "@"); i > 0 { // i>0: a leading '@' is a scope, not a version sep
		return s[:i], s[i+1:]
	}
	return s, ""
}

func isKnownEcosystem(eco string) bool {
	for _, k := range checkEcosystems {
		if k == eco {
			return true
		}
	}
	return false
}
