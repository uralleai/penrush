package forumscan

import (
	"bytes"
	"strings"
	"testing"
)

// okResult builds a successfully-searched forum result with the given hits.
func okResult(forum string, hits ...Hit) Result {
	return Result{Forum: forum, Status: statusOK, Searched: true, Reason: "searched", Hits: hits}
}

// uncheckedResult builds an unchecked forum result.
func uncheckedResult(forum string) Result {
	return Result{Forum: forum, Status: statusUnchecked, Reason: "unreachable"}
}

func redflagHit() Hit {
	return Hit{Title: "pkg is malware", URL: "https://x", MatchedTerms: []string{"malware"}, Stop: true}
}

func reviewHit() Hit {
	return Hit{Title: "pkg hijack rumor", URL: "https://y", MatchedTerms: []string{"hijack"}, Stop: false}
}

// TestAggregateCleanRequiresFullCoverage: CLEAN only when ALL forums searched
// and there are zero red-flag hits.
func TestAggregateCleanRequiresFullCoverage(t *testing.T) {
	res := []Result{
		okResult("Hacker News"), okResult("Stack Exchange"), okResult("Lobsters"),
		okResult("GitHub Discussions"), okResult("Bluesky"),
	}
	agg := aggregate(res)
	if agg.Verdict != VerdictClean {
		t.Fatalf("all searched, no hits → CLEAN, got %s (%s)", agg.Verdict, agg.Note)
	}
	if agg.SearchedCount != 5 {
		t.Errorf("searched_count = %d, want 5", agg.SearchedCount)
	}
}

// TestAggregateFailClosedFloor is the CRITICAL invariant: an unchecked forum
// must NEVER yield CLEAN even with zero hits everywhere else.
func TestAggregateFailClosedFloor(t *testing.T) {
	res := []Result{
		okResult("Hacker News"), okResult("Stack Exchange"), okResult("Lobsters"),
		okResult("GitHub Discussions"),
		uncheckedResult("Bluesky"), // one unchecked, no hits anywhere
	}
	agg := aggregate(res)
	if agg.Verdict == VerdictClean {
		t.Fatalf("fail-closed floor VIOLATED: 1 unchecked forum must NOT be CLEAN, got %s", agg.Verdict)
	}
	if agg.Verdict != VerdictReview {
		t.Fatalf("1 unchecked, no hits → REVIEW, got %s (%s)", agg.Verdict, agg.Note)
	}
	if len(agg.Unchecked) != 1 || agg.Unchecked[0].Forum != "Bluesky" {
		t.Errorf("REVIEW must name the unchecked forum, got %+v", agg.Unchecked)
	}
}

// TestAggregateFlagWinsRegardlessOfCoverage: a single red-flag hit → FLAG even
// when other forums are unchecked (a hit always wins).
func TestAggregateFlagWinsRegardlessOfCoverage(t *testing.T) {
	res := []Result{
		okResult("Hacker News", redflagHit()),
		uncheckedResult("Stack Exchange"),
		uncheckedResult("Lobsters"),
		uncheckedResult("GitHub Discussions"),
		uncheckedResult("Bluesky"),
	}
	agg := aggregate(res)
	if agg.Verdict != VerdictFlag {
		t.Fatalf("any red-flag hit → FLAG, got %s (%s)", agg.Verdict, agg.Note)
	}
	if agg.Summary.FlagHits != 1 {
		t.Errorf("flag_hits = %d, want 1", agg.Summary.FlagHits)
	}
}

// TestAggregateReviewVsFlagAccounting distinguishes review-worthy (non-stop) and
// flag-worthy (stop) hits.
func TestAggregateReviewVsFlagAccounting(t *testing.T) {
	res := []Result{
		okResult("Hacker News", reviewHit()), // non-stop red flag → still FLAG verdict
		okResult("Stack Exchange"), okResult("Lobsters"),
		okResult("GitHub Discussions"), okResult("Bluesky"),
	}
	agg := aggregate(res)
	if agg.Verdict != VerdictFlag {
		t.Fatalf("any red-flag term (even non-stop) → FLAG, got %s", agg.Verdict)
	}
	if agg.Summary.ReviewHits != 1 || agg.Summary.FlagHits != 0 {
		t.Errorf("accounting off: review=%d flag=%d, want review=1 flag=0", agg.Summary.ReviewHits, agg.Summary.FlagHits)
	}
}

func TestExitCodeMapping(t *testing.T) {
	cases := map[string]int{VerdictClean: 0, VerdictReview: 1, VerdictFlag: 2, "unknown": 1}
	for v, want := range cases {
		if got := ExitCode(v); got != want {
			t.Errorf("ExitCode(%q) = %d, want %d", v, got, want)
		}
	}
}

func TestRedFlagClassification(t *testing.T) {
	s := NewScanner("npm", "")
	tokens := tokenVariants("leftpad")

	// Token present + red-flag term → matched.
	if got := s.scan("leftpad is malware now", tokens); len(got) == 0 {
		t.Errorf("expected a red-flag match for 'leftpad is malware', got none")
	}
	// Red-flag term but token ABSENT → no match (the AND-with-token guard).
	if got := s.scan("some other malware story", tokens); len(got) != 0 {
		t.Errorf("token absent must yield no match, got %v", got)
	}
	// No red-flag term → no match.
	if got := s.scan("leftpad is a nice package", tokens); len(got) != 0 {
		t.Errorf("no red-flag term must yield no match, got %v", got)
	}
	// Stop (escalation) subset.
	if !s.isStop("this package has a backdoor") {
		t.Errorf("'backdoor' must be a STOP-level hit")
	}
	if !s.isStop("see CVE-2026-0001") {
		t.Errorf("a CVE ref must be a STOP-level hit")
	}
	if s.isStop("possible hijack chatter") {
		t.Errorf("'hijack' is red-flag but NOT stop-level")
	}
}

func TestEcosystemWidening(t *testing.T) {
	tokens := tokenVariants("leftpad")
	text := "leftpad ships a postinstall script"
	if got := NewScanner("npm", "").scan(text, tokens); len(got) == 0 {
		t.Errorf("npm scanner must widen to 'postinstall', got no match")
	}
	if got := NewScanner("go", "").scan(text, tokens); len(got) != 0 {
		t.Errorf("go scanner must NOT match npm-only 'postinstall', got %v", got)
	}
}

func TestTokenVariants(t *testing.T) {
	got := tokenVariants("ua-parser-js")
	want := map[string]bool{"ua-parser-js": true, "uaparserjs": true, "parser": true}
	for w := range want {
		if !contains(got, w) {
			t.Errorf("tokenVariants missing %q; got %v", w, got)
		}
	}
	// Sub-4-char segments dropped.
	if contains(got, "ua") || contains(got, "js") {
		t.Errorf("short segments must be dropped; got %v", got)
	}
	// owner/repo → repo half included.
	if r := tokenVariants("someowner/coolrepo"); !contains(r, "coolrepo") {
		t.Errorf("owner/repo must include the repo half; got %v", r)
	}
}

func TestMarkerForForum(t *testing.T) {
	if m := markerForForum(uncheckedResult("X")); m != markUnchk {
		t.Errorf("unchecked marker = %q, want %q", m, markUnchk)
	}
	if m := markerForForum(okResult("X")); m != markOK {
		t.Errorf("clean marker = %q, want %q", m, markOK)
	}
	if m := markerForForum(okResult("X", reviewHit())); m != markWarn {
		t.Errorf("review marker = %q, want %q", m, markWarn)
	}
	if m := markerForForum(okResult("X", redflagHit())); m != markFlag {
		t.Errorf("flag marker = %q, want %q", m, markFlag)
	}
}

func TestRenderHonestFraming(t *testing.T) {
	res := []Result{
		okResult("Hacker News"), okResult("Stack Exchange"), okResult("Lobsters"),
		uncheckedResult("GitHub Discussions"), uncheckedResult("Bluesky"),
	}
	agg := aggregate(res)
	var b bytes.Buffer
	Render(&b, agg, "left-pad")
	out := b.String()
	for _, want := range []string{
		"FIELD-TEST", "ADVISORY", "Absence of hits is NOT proof of",
		"FLAG means INVESTIGATE", "AGGREGATE: " + VerdictReview, "unchecked:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Render output missing %q\n---\n%s", want, out)
		}
	}
}

func TestBlueskyWebURL(t *testing.T) {
	uri := "at://did:plc:abc123/app.bsky.feed.post/xyz789"
	want := "https://bsky.app/profile/did:plc:abc123/post/xyz789"
	if got := blueskyWebURL(uri); got != want {
		t.Errorf("blueskyWebURL = %q, want %q", got, want)
	}
	if got := blueskyWebURL("at://did:plc:abc/app.bsky.actor.profile/self"); got != "" {
		t.Errorf("non-post URI must return empty, got %q", got)
	}
}

func TestContainsClass(t *testing.T) {
	if !containsClass("story u-url link", "u-url") {
		t.Error("expected u-url to be found among classes")
	}
	if containsClass("u-url-ish other", "u-url") {
		t.Error("must match whole class token, not substring")
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("abcdef", 3); got != "abc" {
		t.Errorf("truncateRunes = %q, want abc", got)
	}
	// Multi-byte: 2 runes of a 3-rune string.
	if got := truncateRunes("héllo", 2); got != "hé" {
		t.Errorf("rune-safe truncate = %q, want hé", got)
	}
}

func TestResolveGitHubTokenExplicitAndEnv(t *testing.T) {
	if got := ResolveGitHubToken("explicit-tok"); got != "explicit-tok" {
		t.Errorf("explicit token must win, got %q", got)
	}
	t.Setenv("GITHUB_TOKEN", "env-tok")
	if got := ResolveGitHubToken(""); got != "env-tok" {
		t.Errorf("empty explicit must fall back to $GITHUB_TOKEN, got %q", got)
	}
}
