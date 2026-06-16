// Package audit implements the SHA-256-chained, append-only JSONL audit log
// (~/.penrush/audit.jsonl).
//
// Architecture ref: SB.2 (NFR-004). entry_hash = SHA-256(prev_hash ||
// canonical_json(entry_without_hash_fields)); genesis hashes a fixed
// domain-separation string. Canonical JSON = sorted keys, no insignificant
// whitespace, UTF-8.
//
// Honest limitation (stated in the architecture, restated here): a local
// attacker with the user's privileges can delete and re-forge the entire
// log. The chain gives tamper-EVIDENCE against partial edits, not
// tamper-PROOFING against full replacement.
//
// Credential redaction (FR-011): Append runs redact.String over the Command
// field unconditionally. No caller can write an unredacted command.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/penrush/penrush/internal/redact"
)

// genesisDomain is the domain-separation string hashed as the prev_hash of
// the first entry. Changing it is a chain-format break (schema_version bump).
const genesisDomain = "penrush-audit-chain-v1"

// SchemaVersion of the audit entry format.
const SchemaVersion = 1

// Decision values for an audit entry.
const (
	DecisionPass          = "pass"
	DecisionWarn          = "warn"
	DecisionBlock         = "block"
	DecisionOverrideUsed  = "override_used"
	DecisionOverrideAdded = "override_added"
	DecisionInternalError = "internal_error_block" // SC.6 panic-recovery path (M-11 distinguishes it)
)

// Entry is one audit event. Field set per PRD v1.1 S5.6 plus chain fields.
type Entry struct {
	SchemaVersion int      `json:"schema_version"`
	Seq           int64    `json:"seq"`
	TS            string   `json:"ts"` // ISO-8601 UTC
	Command       string   `json:"command"`
	Decision      string   `json:"decision"`
	GatesRun      []string `json:"gates_run"`
	GatesPassed   []string `json:"gates_passed"`
	GatesFailed   []string `json:"gates_failed"`
	Reason        string   `json:"reason"`
	Actor         string   `json:"actor"`
	PolicySource  string   `json:"policy_source"`
	OverrideKey   string   `json:"override_key,omitempty"`
	PrevHash      string   `json:"prev_hash"`
	EntryHash     string   `json:"entry_hash"`
}

// GenesisHash returns the prev_hash value of the first entry.
func GenesisHash() string {
	h := sha256.Sum256([]byte(genesisDomain))
	return "sha256:" + hex.EncodeToString(h[:])
}

// canonicalJSON marshals v as canonical JSON: object keys sorted, no
// insignificant whitespace, UTF-8. Go's encoding/json already sorts map
// keys, so we round-trip the struct through a map.
func canonicalJSON(e Entry) ([]byte, error) {
	// Strip hash fields; they are not part of the hashed content.
	e.PrevHash = ""
	e.EntryHash = ""
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	delete(m, "prev_hash")
	delete(m, "entry_hash")
	return marshalSorted(m)
}

// marshalSorted produces deterministic JSON for a map (encoding/json sorts
// map keys; nested maps inherit the property; slices keep order).
func marshalSorted(m map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf := []byte{'{'}
	for i, k := range keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		vb, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		buf = append(buf, kb...)
		buf = append(buf, ':')
		buf = append(buf, vb...)
	}
	return append(buf, '}'), nil
}

func entryHash(prevHash string, canonical []byte) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(canonical)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Log is an append-only handle on the audit file.
type Log struct {
	path string
}

// Open returns a Log for the given audit.jsonl path. The file is created
// lazily on first Append.
func Open(path string) *Log { return &Log{path: path} }

// tail reads the last entry (if any) to chain from. Returns seq=0,
// prev=GenesisHash() for an empty/missing log.
func (l *Log) tail() (lastSeq int64, lastHash string, err error) {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return 0, GenesisHash(), nil
	}
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var last *Entry
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return 0, "", fmt.Errorf("corrupt audit line before append: %w", err)
		}
		last = &e
	}
	if err := sc.Err(); err != nil {
		return 0, "", err
	}
	if last == nil {
		return 0, GenesisHash(), nil
	}
	return last.Seq, last.EntryHash, nil
}

// Append writes e as the next chained entry. Seq, TS (if empty), hashes and
// schema version are filled in here. The Command field is credential-redacted
// unconditionally (FR-011).
func (l *Log) Append(e Entry) (Entry, error) {
	lastSeq, prevHash, err := l.tail()
	if err != nil {
		return Entry{}, err
	}
	e.SchemaVersion = SchemaVersion
	e.Seq = lastSeq + 1
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339)
	}
	e.Command = redact.String(e.Command)
	if e.GatesRun == nil {
		e.GatesRun = []string{}
	}
	if e.GatesPassed == nil {
		e.GatesPassed = []string{}
	}
	if e.GatesFailed == nil {
		e.GatesFailed = []string{}
	}
	e.PrevHash = prevHash
	canon, err := canonicalJSON(e)
	if err != nil {
		return Entry{}, err
	}
	e.EntryHash = entryHash(prevHash, canon)

	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// VerifyResult reports the outcome of a chain walk.
type VerifyResult struct {
	Entries  int
	OK       bool
	BadSeq   int64  // first failing seq (0 when OK)
	BadField string // what failed: "prev_hash" | "entry_hash" | "seq" | "parse"
}

// Verify re-walks the whole chain. Any edit, deletion, insertion, or
// reorder of a prior entry breaks verification.
func (l *Log) Verify() (VerifyResult, error) {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return VerifyResult{Entries: 0, OK: true}, nil
	}
	if err != nil {
		return VerifyResult{}, err
	}
	defer f.Close()

	res := VerifyResult{OK: true}
	prev := GenesisHash()
	var expectSeq int64 = 1
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			res.OK, res.BadSeq, res.BadField = false, expectSeq, "parse"
			return res, nil
		}
		res.Entries++
		if e.Seq != expectSeq {
			res.OK, res.BadSeq, res.BadField = false, e.Seq, "seq"
			return res, nil
		}
		if e.PrevHash != prev {
			res.OK, res.BadSeq, res.BadField = false, e.Seq, "prev_hash"
			return res, nil
		}
		canon, err := canonicalJSON(e)
		if err != nil {
			res.OK, res.BadSeq, res.BadField = false, e.Seq, "parse"
			return res, nil
		}
		if entryHash(e.PrevHash, canon) != e.EntryHash {
			res.OK, res.BadSeq, res.BadField = false, e.Seq, "entry_hash"
			return res, nil
		}
		prev = e.EntryHash
		expectSeq++
	}
	if err := sc.Err(); err != nil {
		return VerifyResult{}, err
	}
	return res, nil
}

// ReadAll returns every entry in order (for `penrush stats`).
func (l *Log) ReadAll() ([]Entry, error) {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
