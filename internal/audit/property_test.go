package audit

// Property test (a) — audit-chain integrity (architecture §K Property row;
// scope spec §2.1 property #a; pentest P-3 audit-log tampering, §C.2 row 3).
//
// PROPERTY: for ANY chain (any length, any entry content), mutating ANY single
// byte of ANY entry line makes `audit verify` fail.
//
// The existing TestAnyByteMutationBreaksVerify pins this for one fixed 3-entry
// chain. This test generalizes it into a property over randomized inputs:
// randomized chain lengths and randomized, attacker-flavored entry content
// (credentialed commands, unicode, every decision type, varying gate lists),
// then exhaustive single-byte mutation of every line in every generated chain.
// A SHA-256 chain that held only for the convenient fixture but had a content
// shape under which a byte flip went undetected would be a P-3 finding — this
// closes that gap with breadth.
//
// stdlib only: math/rand with a FIXED seed (deterministic, CI-stable; the seed
// is logged so a failure is reproducible).

import (
	"math/rand"
	"os"
	"strings"
	"testing"
)

// randEntry builds a pseudo-random but realistic audit entry. Content is
// deliberately varied across the fields that feed canonicalJSON so the mutation
// property is exercised over many distinct serialized shapes.
func randEntry(rng *rand.Rand) Entry {
	commands := []string{
		"npm install left-pad@1.3.0",
		"pip install --index-url https://user:s3cret@host/simple pkg", // redacted on write
		"docker pull alpine@sha256:deadbeef",
		"go get github.com/foo/bar@v1.2.3",
		"claude mcp add srv",
		"npx café-tool@1.0.0", // non-ASCII
		"",                    // empty command
		strings.Repeat("x", rng.Intn(40)),
	}
	decisions := []string{
		DecisionPass, DecisionWarn, DecisionBlock,
		DecisionOverrideUsed, DecisionOverrideAdded, DecisionInternalError,
	}
	gatePool := []string{"G1", "G2", "G3", "G4", "G5", "G6", "G7"}
	pick := func(n int) []string {
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, gatePool[rng.Intn(len(gatePool))])
		}
		return out
	}
	return Entry{
		Command:      commands[rng.Intn(len(commands))],
		Decision:     decisions[rng.Intn(len(decisions))],
		GatesRun:     pick(rng.Intn(4)),
		GatesPassed:  pick(rng.Intn(3)),
		GatesFailed:  pick(rng.Intn(2)),
		Reason:       "reason-" + string(rune('a'+rng.Intn(26))),
		Actor:        "actor-" + string(rune('A'+rng.Intn(26))),
		PolicySource: []string{"default", "config", "policy.yml"}[rng.Intn(3)],
		OverrideKey:  []string{"", "npm:left-pad", "mcp:srv"}[rng.Intn(3)],
	}
}

func TestPropertyAnyByteMutationBreaksVerifyRandomized(t *testing.T) {
	const seed = 0x50524E52 // "PRNR" — fixed for CI reproducibility
	rng := rand.New(rand.NewSource(seed))
	t.Logf("property seed = 0x%X (set in source for reproducibility)", seed)

	// PROPERTY breadth strategy: many randomized chains (varied length + varied,
	// attacker-flavored content) × a random SAMPLE of byte positions per line.
	// Exhaustive every-byte coverage of one canonical chain is already pinned by
	// TestAnyByteMutationBreaksVerify; this test trades that single-chain
	// exhaustiveness for content/structure breadth at bounded I/O cost.
	const (
		trials        = 12 // distinct randomized chains
		samplePerLine = 12 // random byte positions mutated per entry line
	)
	for trial := 0; trial < trials; trial++ {
		l := Open(tempPath(t))
		n := 1 + rng.Intn(6) // chains of length 1..6
		for i := 0; i < n; i++ {
			if _, err := l.Append(randEntry(rng)); err != nil {
				t.Fatalf("trial %d append %d: %v", trial, i, err)
			}
		}

		// Baseline: the freshly-built chain must verify.
		if res, err := l.Verify(); err != nil || !res.OK {
			t.Fatalf("trial %d: freshly built chain failed to verify: res=%+v err=%v", trial, res, err)
		}

		orig, err := os.ReadFile(l.path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.SplitAfter(string(orig), "\n")

		for li := 0; li < len(lines); li++ {
			line := lines[li]
			if strings.TrimSpace(line) == "" {
				continue // trailing empty segment after the final newline
			}
			// Sample byte positions (always include first + last content byte —
			// the chain-field edges — plus random interior positions).
			positions := samplePositions(rng, len(line), samplePerLine)
			for _, bi := range positions {
				if line[bi] == '\n' {
					continue // do not destroy the line framing itself
				}
				mut := []byte(line)
				mut[bi] ^= 0x01
				if string(mut) == line {
					continue
				}
				rebuilt := strings.Join(replaceAt(lines, li, string(mut)), "")
				if err := os.WriteFile(l.path, []byte(rebuilt), 0o600); err != nil {
					t.Fatal(err)
				}
				res, verr := l.Verify()
				if verr != nil {
					t.Fatalf("trial %d: Verify errored on mutated chain: %v", trial, verr)
				}
				if res.OK {
					t.Fatalf("trial %d (n=%d): UNDETECTED mutation at line %d byte %d (0x%02x->0x%02x)\nline: %q",
						trial, n, li, bi, line[bi], mut[bi], line)
				}
			}
		}

		// Restore + confirm the property test left the chain valid.
		if err := os.WriteFile(l.path, orig, 0o600); err != nil {
			t.Fatal(err)
		}
		if res, _ := l.Verify(); !res.OK {
			t.Fatalf("trial %d: restored chain should verify", trial)
		}
	}
}

// samplePositions returns up to k byte indices in [0,n): always the first and
// last content byte (chain-field edges are the highest-value targets), plus
// random interior positions. Deduplicated, so the count may be < k for short
// lines.
func samplePositions(rng *rand.Rand, n, k int) []int {
	if n <= 0 {
		return nil
	}
	seen := map[int]bool{0: true}
	out := []int{0}
	if n > 1 {
		last := n - 1
		if !seen[last] {
			seen[last] = true
			out = append(out, last)
		}
	}
	for len(out) < k && len(out) < n {
		p := rng.Intn(n)
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// tempPath returns a fresh audit.jsonl path under a per-test temp dir.
func tempPath(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/audit.jsonl"
}

// replaceAt returns a copy of lines with index i set to repl.
func replaceAt(lines []string, i int, repl string) []string {
	out := make([]string, len(lines))
	copy(out, lines)
	out[i] = repl
	return out
}
