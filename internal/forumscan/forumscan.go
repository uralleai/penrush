// Package forumscan is a Go port of DSPC Gate 4b — the cross-forum
// "community review research" scanner. Given a package name (or owner/repo) it
// searches a set of free, keyless (except an optional GitHub PAT) public forums
// for prior human discussion of the artifact being compromised / malicious /
// hijacked, classifies each hit by a red-flag term set, and emits a fail-closed
// aggregate verdict.
//
// Forums (verified free endpoints):
//   - Hacker News        — Algolia HN Search API (PRIMARY)   — no auth
//   - Stack Exchange     — Stack Overflow + Security SE       — keyless (gzip!)
//   - Lobsters           — lobste.rs HTML search              — no auth (HTML only)
//   - GitHub Discussions — cross-repo GraphQL search          — needs free PAT
//   - Bluesky            — public AppView searchPosts         — no auth
//
// Design doctrine (ported verbatim from scripts/dspc-forum-scan.py, learned
// from live testing):
//   - Do NOT AND the package name with red-flag words in one server-side query —
//     it silently returns 0 hits even on famously-compromised packages. Query
//     the BARE package name, then regex-scan client-side for red-flag terms.
//   - A forum that errors/times out is reported UNCHECKED — NEVER counted clean.
//   - Fail-closed verdict floor: CLEAN requires ALL 5 forums to have been
//     successfully searched AND zero red-flag hits. ANY red-flag hit on ANY
//     successfully-searched forum → FLAG. Every other no-red-flag case (≥1 forum
//     unchecked) → REVIEW. An unchecked forum NEVER contributes to CLEAN.
//   - "Empty" from a low-recall source (Stack Exchange) != "safe".
//   - GitHub token resolution order: explicit arg, then $GITHUB_TOKEN, then
//     `gh auth token` (GitHub CLI). Only if all three fail is the forum UNCHECKED.
//
// This is advisory and makes OUTBOUND network calls — the rest of PenRUSH stays
// offline and zero-telemetry. It is stdlib-only (net/http, encoding/json,
// regexp, compress/gzip, os/exec for `gh auth token`), read-only, and transmits
// no PII except an optional GitHub token as an Authorization: Bearer header to
// api.github.com.
package forumscan

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// UserAgent is the descriptive User-Agent sent on every request.
	UserAgent = "penrush-forumscan/0.2 (supply-chain safety research; +https://penbag.store)"
	// perRequestTimeout bounds each individual HTTP request (mirrors the Python
	// PER_REQUEST_TIMEOUT). A forum that makes several requests is bounded per
	// request; the RunScan-level recover bounds the rest.
	perRequestTimeout = 8 * time.Second
	// ghAuthTokenTimeout bounds the `gh auth token` subprocess.
	ghAuthTokenTimeout = 5 * time.Second
	// maxBodyBytes caps a response body read (pre- and post-gzip) so a
	// pathological response cannot exhaust memory. These are known advisory APIs,
	// not the payload scanner — a generous ceiling is fine.
	maxBodyBytes = 16 << 20
)

// Verdict values (exit-code mapping: CLEAN 0, REVIEW 1, FLAG 2).
const (
	VerdictClean  = "CLEAN"
	VerdictReview = "REVIEW"
	VerdictFlag   = "FLAG"
)

// ASCII-only markers (no emoji, no box-drawing) — Unicode-safe on any terminal.
const (
	markOK    = "[OK]" // searched, no hits
	markWarn  = "[!]"  // red-flag hit → REVIEW-worthy
	markFlag  = "[X]"  // explicit-compromise hit → FLAG
	markUnchk = "[?]"  // unchecked forum
)

// statusOK / statusUnchecked are the two Result.Status values.
const (
	statusOK        = "ok"
	statusUnchecked = "unchecked"
)

// Broad red-flag roots → any match makes a hit worth REVIEW. Escalation subset
// (stopPattern) → any match makes the hit a FLAG (explicit compromise). Kept as
// raw patterns (no inline flag) so a per-ecosystem widened variant can be
// compiled cleanly.
const (
	redFlagPattern = `malici|comprom|hijack|backdoor|trojan|malware|cryptomin|steal|exfil|` +
		`poison|typosquat|worm|do ?not ?install|supply[ -]?chain`
	stopPattern = `comprom|backdoor|trojan|malware|do ?not ?install|cve-\d|ghsa-`
)

var (
	redFlagRoots = regexp.MustCompile(`(?i)` + redFlagPattern)
	stopRoots    = regexp.MustCompile(`(?i)` + stopPattern)
	nonAlnum     = regexp.MustCompile(`[^a-z0-9]+`)

	// Lobsters HTML-scrape helpers (stdlib has no DOM parser; regexp only).
	anchorRe = regexp.MustCompile(`(?is)<a\b([^>]*)>(.*?)</a>`)
	hrefRe   = regexp.MustCompile(`(?i)href="([^"]*)"`)
	classRe  = regexp.MustCompile(`(?i)class="([^"]*)"`)
	htmlTag  = regexp.MustCompile(`(?s)<[^>]*>`)
)

// ecosystemExtra widens the red-flag set per ecosystem (tunes the term set ONLY,
// never the endpoints).
var ecosystemExtra = map[string]string{
	"npm":   `postinstall|preinstall|prepublish`,
	"pypi":  `setup\.py|sdist backdoor`,
	"cargo": `build\.rs`,
	"gem":   `extconf`,
	"go":    `go ?generate`,
}

// Hit is one red-flag match within a forum result.
type Hit struct {
	Title        string   `json:"title"`
	URL          string   `json:"url"`
	Date         string   `json:"date"`
	MatchedTerms []string `json:"matched_terms"`
	Stop         bool     `json:"stop"`
}

// Result is one forum's outcome. Status is statusOK or statusUnchecked; an
// unchecked forum NEVER contributes to a CLEAN verdict.
type Result struct {
	Forum    string `json:"forum"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
	Searched bool   `json:"searched"`
	Hits     []Hit  `json:"hits"`
}

// Unchecked names a forum that could not be searched and why.
type Unchecked struct {
	Forum  string `json:"forum"`
	Reason string `json:"reason"`
}

// Summary is the roll-up hit accounting.
type Summary struct {
	HitsTotal  int      `json:"hits_total"`
	FlagHits   int      `json:"flag_hits"`
	ReviewHits int      `json:"review_hits"`
	Searched   []string `json:"searched"`
}

// Aggregate is the whole-scan verdict.
type Aggregate struct {
	Verdict       string      `json:"verdict"`
	Note          string      `json:"note"`
	Forums        []Result    `json:"forums"`
	SearchedCount int         `json:"searched_count"`
	Unchecked     []Unchecked `json:"unchecked"`
	Summary       Summary     `json:"summary"`
}

// Scanner holds the effective (per-ecosystem-widened) red-flag matchers, the
// HTTP client, and the resolved GitHub token. It carries no global mutable
// state — build one per scan with NewScanner.
type Scanner struct {
	redFlag *regexp.Regexp
	stop    *regexp.Regexp
	client  *http.Client
	ghToken string
}

// NewScanner builds a scanner for one ecosystem with an already-resolved GitHub
// token (see ResolveGitHubToken). An empty token marks GitHub Discussions
// UNCHECKED — it never fabricates a clean result.
func NewScanner(ecosystem, githubToken string) *Scanner {
	red := redFlagRoots
	if extra, ok := ecosystemExtra[ecosystem]; ok && extra != "" {
		red = regexp.MustCompile(`(?i)` + redFlagPattern + `|` + extra)
	}
	return &Scanner{
		redFlag: red,
		stop:    stopRoots,
		client:  &http.Client{Timeout: perRequestTimeout},
		ghToken: githubToken,
	}
}

// Scan is the package-level convenience: build a scanner for ecosystem with the
// resolved token and search all five forums for target.
func Scan(ctx context.Context, target, ecosystem, githubToken string) Aggregate {
	return NewScanner(ecosystem, githubToken).RunScan(ctx, target)
}

// RunScan searches all five forums for target and returns the fail-closed
// aggregate. Each forum runs under a panic-recover so a single forum failing
// neither crashes the scan nor silently passes (a recovered panic → that forum
// is unchecked, never clean).
func (s *Scanner) RunScan(ctx context.Context, target string) Aggregate {
	forums := []struct {
		name string
		fn   func(context.Context, string) Result
	}{
		{"Hacker News", s.searchHackerNews}, // PRIMARY
		{"Stack Exchange", s.searchStackExchange},
		{"Lobsters", s.searchLobsters},
		{"GitHub Discussions", s.searchGitHubDiscussions},
		{"Bluesky", s.searchBluesky},
	}
	results := make([]Result, 0, len(forums))
	for _, f := range forums {
		results = append(results, safeForum(ctx, f.name, target, f.fn))
	}
	return aggregate(results)
}

// safeForum runs one forum function under a recover so a panic becomes an
// UNCHECKED result rather than crashing the scan or silently passing.
func safeForum(ctx context.Context, name, target string, fn func(context.Context, string) Result) (res Result) {
	defer func() {
		if r := recover(); r != nil {
			res = Result{Forum: name, Status: statusUnchecked, Reason: fmt.Sprintf("recovered panic: %v", r)}
		}
	}()
	return fn(ctx, target)
}

// aggregate applies the fail-closed verdict floor (CRITICAL — do not weaken):
//
//	FLAG   — ANY red-flag-term hit on ANY successfully-searched forum. Checked
//	         first; a hit always wins regardless of coverage elsewhere.
//	CLEAN  — ONLY if zero red-flag hits AND every one of the forums was
//	         successfully searched (unchecked count == 0).
//	REVIEW — every other no-red-flag case: no red-flag hits but ≥1 forum
//	         UNCHECKED. An unchecked forum must NEVER contribute to CLEAN.
func aggregate(results []Result) Aggregate {
	var reachable, unchecked []Result
	for _, r := range results {
		if r.Status == statusOK {
			reachable = append(reachable, r)
		} else {
			unchecked = append(unchecked, r)
		}
	}
	var allHits []Hit
	for _, r := range reachable {
		allHits = append(allHits, r.Hits...)
	}
	hasRedflag := false
	for _, h := range allHits {
		if len(h.MatchedTerms) > 0 {
			hasRedflag = true
			break
		}
	}

	var verdict, note string
	switch {
	case hasRedflag:
		verdict = VerdictFlag
		note = fmt.Sprintf("%d red-flag hit(s) across %d successfully-searched forum(s) -- treat as STOP-candidate",
			len(allHits), len(reachable))
	case len(unchecked) == 0:
		verdict = VerdictClean
		note = fmt.Sprintf("all %d/%d forums searched, zero red-flag hits", len(results), len(results))
	default:
		names := make([]string, 0, len(unchecked))
		for _, u := range unchecked {
			names = append(names, u.Forum)
		}
		verdict = VerdictReview
		note = fmt.Sprintf("REVIEW -- %d/%d forums searched, %d unchecked (%s): cannot certify CLEAN without full coverage",
			len(reachable), len(results), len(unchecked), strings.Join(names, ", "))
	}

	uncheckedOut := make([]Unchecked, 0, len(unchecked))
	for _, u := range unchecked {
		uncheckedOut = append(uncheckedOut, Unchecked{Forum: u.Forum, Reason: u.Reason})
	}
	searched := make([]string, 0, len(reachable))
	for _, r := range reachable {
		searched = append(searched, r.Forum)
	}
	flagHits, reviewHits := 0, 0
	for _, h := range allHits {
		switch {
		case h.Stop:
			flagHits++
		case len(h.MatchedTerms) > 0:
			reviewHits++
		}
	}
	return Aggregate{
		Verdict:       verdict,
		Note:          note,
		Forums:        results,
		SearchedCount: len(reachable),
		Unchecked:     uncheckedOut,
		Summary:       Summary{HitsTotal: len(allHits), FlagHits: flagHits, ReviewHits: reviewHits, Searched: searched},
	}
}

// ExitCode maps a verdict to the CLI exit convention: CLEAN 0, REVIEW 1, FLAG 2.
func ExitCode(verdict string) int {
	switch verdict {
	case VerdictClean:
		return 0
	case VerdictFlag:
		return 2
	default:
		return 1
	}
}

// ResolveGitHubToken returns a GitHub token for the Discussions search, trying
// in order: the explicit argument, then $GITHUB_TOKEN, then `gh auth token`
// (GitHub CLI). It NEVER panics and NEVER returns an error — if all three fail
// it returns "" and the caller marks GitHub Discussions UNCHECKED (never clean).
func ResolveGitHubToken(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit)
	}
	if t := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); t != "" {
		return t
	}
	return tryGHAuthToken()
}

// tryGHAuthToken shells out to `gh auth token`. Returns "" if gh is missing, not
// authenticated, or errors for any reason — never a false token.
func tryGHAuthToken() string {
	ctx, cancel := context.WithTimeout(context.Background(), ghAuthTokenTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ------------------------------------------------------------------------- //
// Matching helpers
// ------------------------------------------------------------------------- //

// tokenVariants builds the set of tokens that count as "the package is
// referenced", e.g. ua-parser-js → [parser, ua-parser-js, uaparserjs]; drops
// sub-4-char segments; owner/repo → also the repo half.
func tokenVariants(pkg string) []string {
	p := strings.ToLower(strings.TrimSpace(pkg))
	set := map[string]struct{}{}
	if p != "" {
		set[p] = struct{}{}
	}
	if strings.Contains(p, "/") {
		parts := strings.Split(p, "/")
		repo := parts[len(parts)-1]
		if repo != "" {
			set[repo] = struct{}{}
			p = repo // segment further on the repo name
		}
	}
	if collapsed := nonAlnum.ReplaceAllString(p, ""); collapsed != "" {
		set[collapsed] = struct{}{}
	}
	for _, seg := range nonAlnum.Split(p, -1) {
		if len(seg) > 3 {
			set[seg] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// matches returns the distinct red-flag roots in text, but ONLY if token also
// appears in text. Empty == no red-flag (or token absent).
func (s *Scanner) matches(text, token string) []string {
	if text == "" {
		return nil
	}
	low := strings.ToLower(text)
	if token != "" && !strings.Contains(low, strings.ToLower(token)) {
		return nil
	}
	var seen []string
	for _, f := range s.redFlag.FindAllString(low, -1) {
		f = strings.TrimSpace(f)
		if f != "" && !contains(seen, f) {
			seen = append(seen, f)
		}
	}
	return seen
}

// scan is the union of matches across all token variants.
func (s *Scanner) scan(text string, tokens []string) []string {
	var out []string
	for _, tok := range tokens {
		for _, m := range s.matches(text, tok) {
			if !contains(out, m) {
				out = append(out, m)
			}
		}
	}
	return out
}

// isStop reports whether the escalation (FLAG-worthy) subset matches.
func (s *Scanner) isStop(text string) bool {
	return text != "" && s.stop.MatchString(text)
}

// tokenPresent reports whether any token variant appears in text.
func tokenPresent(text string, tokens []string) bool {
	low := strings.ToLower(text)
	for _, tok := range tokens {
		if tok != "" && strings.Contains(low, strings.ToLower(tok)) {
			return true
		}
	}
	return false
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// truncateRunes truncates s to at most n runes (UTF-8-safe, unlike a byte slice).
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// ------------------------------------------------------------------------- //
// HTTP helpers
// ------------------------------------------------------------------------- //

// httpGet issues a GET with the descriptive UA and manual gzip handling. A
// non-2xx status is NOT an error (the caller branches on the code, mirroring the
// Python HTTPError handling); only a transport/timeout failure returns a non-nil
// error, which the caller reports as UNCHECKED.
func (s *Scanner) httpGet(ctx context.Context, url string, extra map[string]string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, rerr := readBody(resp)
	if rerr != nil {
		return resp.StatusCode, "", rerr
	}
	return resp.StatusCode, body, nil
}

// httpPostJSON POSTs a JSON payload (GitHub GraphQL). Same failure contract as
// httpGet.
func (s *Scanner) httpPostJSON(ctx context.Context, url string, payload any, headers map[string]string) (int, string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, rerr := readBody(resp)
	if rerr != nil {
		return resp.StatusCode, "", rerr
	}
	return resp.StatusCode, body, nil
}

// readBody reads the (size-capped) response body, gzip-decoding when the server
// declares Content-Encoding: gzip. Setting Accept-Encoding: gzip ourselves
// disables Go's transparent decompression, so Stack Exchange's mandatory gzip is
// handled explicitly here. A server that mislabels its encoding falls back to
// the raw bytes rather than erroring.
func readBody(resp *http.Response) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", err
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Encoding")), "gzip") {
		gz, gerr := gzip.NewReader(bytes.NewReader(raw))
		if gerr != nil {
			return string(raw), nil // server lied about gzip → use raw
		}
		defer gz.Close()
		dec, derr := io.ReadAll(io.LimitReader(gz, maxBodyBytes))
		if derr != nil {
			return string(raw), nil // partial/bad gzip → fall back to raw
		}
		return string(dec), nil
	}
	return string(raw), nil
}
