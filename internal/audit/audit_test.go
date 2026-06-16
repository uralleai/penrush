package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempLog(t *testing.T) *Log {
	t.Helper()
	return Open(filepath.Join(t.TempDir(), "audit.jsonl"))
}

func appendN(t *testing.T, l *Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := l.Append(Entry{
			Command:      "npm install left-pad@1.3.0",
			Decision:     DecisionPass,
			GatesRun:     []string{"G1"},
			GatesPassed:  []string{"G1"},
			Reason:       "age ok",
			Actor:        "test@host",
			PolicySource: "default",
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

func TestChainAppendAndVerify(t *testing.T) {
	l := tempLog(t)
	appendN(t, l, 5)
	res, err := l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Entries != 5 {
		t.Fatalf("expected OK with 5 entries, got %+v", res)
	}
}

func TestEmptyLogVerifies(t *testing.T) {
	l := tempLog(t)
	res, err := l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Entries != 0 {
		t.Fatalf("expected OK empty, got %+v", res)
	}
}

func TestSeqAndGenesis(t *testing.T) {
	l := tempLog(t)
	e1, err := l.Append(Entry{Command: "x", Decision: DecisionBlock})
	if err != nil {
		t.Fatal(err)
	}
	if e1.Seq != 1 || e1.PrevHash != GenesisHash() {
		t.Fatalf("genesis chaining wrong: %+v", e1)
	}
	e2, err := l.Append(Entry{Command: "y", Decision: DecisionPass})
	if err != nil {
		t.Fatal(err)
	}
	if e2.Seq != 2 || e2.PrevHash != e1.EntryHash {
		t.Fatalf("second entry not chained to first: %+v", e2)
	}
}

// Property (architecture SK): any single-byte mutation of any entry breaks
// Verify. We mutate every byte position of a mid-chain line (skipping bytes
// where the mutation yields identical content) and require failure each time.
func TestAnyByteMutationBreaksVerify(t *testing.T) {
	l := tempLog(t)
	appendN(t, l, 3)
	orig, err := os.ReadFile(l.path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(orig), "\n")
	target := lines[1] // middle entry
	for i := 0; i < len(target)-1; i++ { // -1: keep trailing newline intact
		mut := []byte(target)
		mut[i] ^= 0x01
		if string(mut) == target {
			continue
		}
		mutated := lines[0] + string(mut) + lines[2]
		if err := os.WriteFile(l.path, []byte(mutated), 0o600); err != nil {
			t.Fatal(err)
		}
		res, err := l.Verify()
		if err != nil {
			t.Fatal(err)
		}
		if res.OK {
			t.Fatalf("mutation at byte %d (0x%02x->0x%02x) NOT detected", i, target[i], mut[i])
		}
	}
	// restore + sanity
	if err := os.WriteFile(l.path, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	res, _ := l.Verify()
	if !res.OK {
		t.Fatal("restored log should verify")
	}
}

func TestDeletionBreaksVerify(t *testing.T) {
	l := tempLog(t)
	appendN(t, l, 3)
	orig, _ := os.ReadFile(l.path)
	lines := strings.SplitAfter(string(orig), "\n")
	// delete the middle entry
	if err := os.WriteFile(l.path, []byte(lines[0]+lines[2]), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("deleting a mid-chain entry must break verification")
	}
}

func TestReorderBreaksVerify(t *testing.T) {
	l := tempLog(t)
	appendN(t, l, 3)
	orig, _ := os.ReadFile(l.path)
	lines := strings.SplitAfter(string(orig), "\n")
	if err := os.WriteFile(l.path, []byte(lines[1]+lines[0]+lines[2]), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("reordering entries must break verification")
	}
}

// FR-011: the audit writer redacts unconditionally — a caller that passes a
// raw credentialed command cannot get it stored in plaintext.
func TestAppendRedactsCommand(t *testing.T) {
	l := tempLog(t)
	secret := "s3cretTOKENvalue"
	_, err := l.Append(Entry{
		Command:  "pip install --index-url https://user:" + secret + "@private.example/simple pkg",
		Decision: DecisionBlock,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(l.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("plaintext secret found in audit.jsonl — FR-011 violated")
	}
	if !strings.Contains(string(raw), "https://user:[REDACTED]@private.example") {
		t.Fatalf("expected redaction marker in stored command, got: %s", raw)
	}
	// chain still verifies after redaction
	res, _ := l.Verify()
	if !res.OK {
		t.Fatal("chain must verify over the redacted content")
	}
}

func TestCanonicalJSONDeterminism(t *testing.T) {
	e := Entry{Command: "x", Decision: "pass", GatesRun: []string{"G1"}, GatesPassed: []string{"G1"}, GatesFailed: []string{}}
	a, err := canonicalJSON(e)
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonicalJSON(e)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("canonical JSON not deterministic")
	}
	// must not contain the hash fields
	var m map[string]any
	if err := json.Unmarshal(a, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["prev_hash"]; ok {
		t.Fatal("prev_hash leaked into canonical content")
	}
	if _, ok := m["entry_hash"]; ok {
		t.Fatal("entry_hash leaked into canonical content")
	}
}
