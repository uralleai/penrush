package forumscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// blank returns an initialized UNCHECKED result for forum.
func blank(forum string) Result {
	return Result{Forum: forum, Status: statusUnchecked}
}

// searchHackerNews is the PRIMARY forum: Algolia HN Search, bare package name,
// client-side red-flag scan.
func (s *Scanner) searchHackerNews(ctx context.Context, pkg string) Result {
	r := blank("Hacker News")
	tokens := tokenVariants(pkg)
	q := url.QueryEscape(pkg)
	u := "https://hn.algolia.com/api/v1/search?query=" + q + "&tags=story&hitsPerPage=50"
	status, body, err := s.httpGet(ctx, u, nil)
	if err != nil {
		r.Reason = "unreachable: " + err.Error()
		return r
	}
	if status != 200 {
		r.Reason = fmt.Sprintf("HTTP %d from Algolia HN search", status)
		return r
	}
	var data struct {
		Hits []struct {
			Title       string `json:"title"`
			StoryTitle  string `json:"story_title"`
			URL         string `json:"url"`
			StoryText   string `json:"story_text"`
			CommentText string `json:"comment_text"`
			ObjectID    string `json:"objectID"`
			CreatedAt   string `json:"created_at"`
		} `json:"hits"`
		NbHits int `json:"nbHits"`
	}
	if jerr := json.Unmarshal([]byte(body), &data); jerr != nil {
		r.Reason = "JSON parse error: " + jerr.Error()
		return r
	}
	r.Searched = true
	for _, h := range data.Hits {
		title := firstNonEmpty(h.Title, h.StoryTitle)
		story := firstNonEmpty(h.StoryText, h.CommentText)
		itemURL := h.URL
		if itemURL == "" && h.ObjectID != "" {
			itemURL = "https://news.ycombinator.com/item?id=" + h.ObjectID
		}
		blob := strings.Join([]string{title, h.URL, story}, " ")
		matched := s.scan(blob, tokens)
		if len(matched) > 0 {
			r.Hits = append(r.Hits, Hit{
				Title:        orUntitled(title),
				URL:          itemURL,
				Date:         h.CreatedAt,
				MatchedTerms: matched,
				Stop:         s.isStop(blob),
			})
		}
	}
	r.Status = statusOK
	r.Reason = fmt.Sprintf("searched bare name; %d raw hits, %d red-flag matches", data.NbHits, len(r.Hits))
	return r
}

// stackExchangeSite queries one SE site. Returns (ok, reason, hits). gzip decode
// is handled in readBody.
func (s *Scanner) stackExchangeSite(ctx context.Context, pkg string, tokens []string, site string) (bool, string, []Hit) {
	q := url.QueryEscape(pkg)
	u := "https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=activity&q=" + q + "&site=" + site + "&pagesize=50"
	status, body, err := s.httpGet(ctx, u, nil)
	if err != nil {
		return false, fmt.Sprintf("%s: unreachable (%v)", site, err), nil
	}
	if status != 200 {
		return false, fmt.Sprintf("HTTP %d from api.stackexchange (%s)", status, site), nil
	}
	var data struct {
		Items []struct {
			Title        string   `json:"title"`
			Link         string   `json:"link"`
			Tags         []string `json:"tags"`
			CreationDate int64    `json:"creation_date"`
		} `json:"items"`
		QuotaRemaining int `json:"quota_remaining"`
	}
	if jerr := json.Unmarshal([]byte(body), &data); jerr != nil {
		return false, fmt.Sprintf("JSON parse error (%s): %v", site, jerr), nil
	}
	var hits []Hit
	for _, it := range data.Items {
		blob := strings.Join([]string{it.Title, it.Link, strings.Join(it.Tags, " ")}, " ")
		matched := s.scan(blob, tokens)
		if len(matched) > 0 {
			date := ""
			if it.CreationDate != 0 {
				date = fmt.Sprintf("%d", it.CreationDate)
			}
			hits = append(hits, Hit{
				Title:        orUntitled(strings.TrimSpace(it.Title)),
				URL:          it.Link,
				Date:         date,
				MatchedTerms: matched,
				Stop:         s.isStop(blob),
			})
		}
	}
	return true, fmt.Sprintf("%s: quota_remaining=%d", site, data.QuotaRemaining), hits
}

// searchStackExchange searches Stack Overflow + Security SE. Status ok even when
// empty, BUT the reason carries the low-recall caveat so the aggregate never
// overstates empty == safe.
func (s *Scanner) searchStackExchange(ctx context.Context, pkg string) Result {
	r := blank("Stack Exchange")
	tokens := tokenVariants(pkg)
	var reasons []string
	anyOK := false
	for _, site := range []string{"stackoverflow", "security"} {
		ok, reason, hits := s.stackExchangeSite(ctx, pkg, tokens, site)
		reasons = append(reasons, reason)
		if ok {
			anyOK = true
			r.Hits = append(r.Hits, hits...)
		}
	}
	if !anyOK {
		r.Reason = strings.Join(reasons, "; ")
		if r.Reason == "" {
			r.Reason = "no SE site reachable"
		}
		return r
	}
	r.Searched = true
	r.Status = statusOK
	r.Reason = "low-recall source; empty != safe -- " + strings.Join(reasons, "; ")
	return r
}

// searchLobsters scrapes the lobste.rs HTML search (no JSON variant). It
// requires the package token to actually appear in a result before counting —
// the site's tokenizer mangles hyphenated names, so this guards against
// 'parser'-noise false positives.
func (s *Scanner) searchLobsters(ctx context.Context, pkg string) Result {
	r := blank("Lobsters")
	tokens := tokenVariants(pkg)
	q := url.QueryEscape(pkg)
	u := "https://lobste.rs/search?q=" + q + "&what=stories&order=newest"
	status, body, err := s.httpGet(ctx, u, map[string]string{"Accept": "text/html"})
	if err != nil {
		r.Reason = "unreachable: " + err.Error()
		return r
	}
	if status != 200 {
		r.Reason = fmt.Sprintf("HTTP %d from lobste.rs search (HTML-only endpoint)", status)
		return r
	}
	r.Searched = true
	stories, counted := 0, 0
	for _, m := range anchorRe.FindAllStringSubmatch(body, -1) {
		attrs, inner := m[1], m[2]
		cls := classRe.FindStringSubmatch(attrs)
		if cls == nil || !containsClass(cls[1], "u-url") {
			continue
		}
		stories++
		href := ""
		if hm := hrefRe.FindStringSubmatch(attrs); hm != nil {
			href = hm[1]
		}
		title := strings.TrimSpace(htmlTag.ReplaceAllString(inner, ""))
		full := href
		if !strings.HasPrefix(href, "http") {
			full = "https://lobste.rs" + href
		}
		blob := strings.Join([]string{title, href}, " ")
		if !tokenPresent(blob, tokens) {
			continue
		}
		counted++
		matched := s.scan(blob, tokens)
		if len(matched) > 0 {
			r.Hits = append(r.Hits, Hit{
				Title:        orUntitled(title),
				URL:          full,
				MatchedTerms: matched,
				Stop:         s.isStop(blob),
			})
		}
	}
	r.Status = statusOK
	r.Reason = fmt.Sprintf("HTML-scraped; %d stories, %d referenced the package token, %d red-flag matches (weak/supplementary signal)",
		stories, counted, len(r.Hits))
	return r
}

// searchGitHubDiscussions runs a cross-repo GitHub Discussions GraphQL search,
// one query per STOP-ish term (no OR grouping — GitHub search ANDs free text and
// would zero out an OR line). Requires a free PAT; without one, returns
// UNCHECKED (never fabricates ok).
func (s *Scanner) searchGitHubDiscussions(ctx context.Context, pkg string) Result {
	r := blank("GitHub Discussions")
	tokens := tokenVariants(pkg)
	if s.ghToken == "" {
		r.Reason = "no GitHub token: explicit flag, $GITHUB_TOKEN, and `gh auth token` (gh CLI) all unavailable; Discussions search needs a free PAT"
		return r
	}
	terms := []string{"compromised", "malicious", "backdoor", "malware"}
	const gql = `query($q: String!) { search(query: $q, type: DISCUSSION, first: 10) { nodes { ... on Discussion { title url createdAt repository { nameWithOwner } } } } }`
	headers := map[string]string{"Authorization": "Bearer " + s.ghToken}
	seen := map[string]bool{}
	anyOK := false
	var reasons []string
	for _, term := range terms {
		payload := map[string]any{"query": gql, "variables": map[string]any{"q": pkg + " " + term}}
		status, body, err := s.httpPostJSON(ctx, "https://api.github.com/graphql", payload, headers)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("'%s': unreachable (%v)", term, err))
			continue
		}
		if status == 401 || status == 403 {
			r.Reason = fmt.Sprintf("HTTP %d from api.github.com/graphql (token invalid/insufficient)", status)
			return r
		}
		if status != 200 {
			reasons = append(reasons, fmt.Sprintf("'%s': HTTP %d", term, status))
			continue
		}
		var data struct {
			Data struct {
				Search struct {
					Nodes []struct {
						Title      string `json:"title"`
						URL        string `json:"url"`
						CreatedAt  string `json:"createdAt"`
						Repository struct {
							NameWithOwner string `json:"nameWithOwner"`
						} `json:"repository"`
					} `json:"nodes"`
				} `json:"search"`
			} `json:"data"`
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if jerr := json.Unmarshal([]byte(body), &data); jerr != nil {
			reasons = append(reasons, fmt.Sprintf("'%s': JSON parse error %v", term, jerr))
			continue
		}
		if len(data.Errors) > 0 {
			reasons = append(reasons, fmt.Sprintf("'%s': graphql errors %s", term, data.Errors[0].Message))
			continue
		}
		anyOK = true
		for _, n := range data.Data.Search.Nodes {
			repo := n.Repository.NameWithOwner
			blob := strings.Join([]string{n.Title, repo}, " ")
			if !tokenPresent(blob, tokens) {
				continue
			}
			if seen[n.URL] {
				continue
			}
			seen[n.URL] = true
			matched := s.scan(strings.Join([]string{n.Title, repo, n.URL}, " "), tokens)
			if len(matched) == 0 {
				matched = []string{term}
			}
			title := strings.TrimSpace(n.Title)
			if repo != "" {
				title += "  (" + repo + ")"
			}
			stop := s.isStop(blob) || term == "compromised" || term == "backdoor" || term == "malware"
			r.Hits = append(r.Hits, Hit{
				Title:        orUntitled(title),
				URL:          n.URL,
				Date:         n.CreatedAt,
				MatchedTerms: matched,
				Stop:         stop,
			})
		}
	}
	if !anyOK {
		r.Reason = strings.Join(reasons, "; ")
		if r.Reason == "" {
			r.Reason = "no GitHub query succeeded"
		}
		return r
	}
	r.Searched = true
	r.Status = statusOK
	r.Reason = fmt.Sprintf("searched %d terms; %d package-referencing red-flag matches", len(terms), len(r.Hits))
	return r
}

// searchBluesky queries the Bluesky public AppView searchPosts. Some egress IPs
// (BunnyCDN edge) get 403; any non-200 is UNCHECKED with an explicit 'verify
// from deploy egress' note.
func (s *Scanner) searchBluesky(ctx context.Context, pkg string) Result {
	r := blank("Bluesky")
	tokens := tokenVariants(pkg)
	q := url.QueryEscape(pkg)
	u := "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=" + q + "&limit=25"
	status, body, err := s.httpGet(ctx, u, nil)
	if err != nil {
		r.Reason = "unreachable: " + err.Error()
		return r
	}
	if status != 200 {
		r.Reason = fmt.Sprintf("HTTP %d: edge/CDN blocked or non-200 from this egress IP (BunnyCDN); verify a 200 from the deploy egress before trusting", status)
		return r
	}
	var data struct {
		Posts []struct {
			URI    string `json:"uri"`
			Author struct {
				Handle string `json:"handle"`
			} `json:"author"`
			Record struct {
				Text      string `json:"text"`
				CreatedAt string `json:"createdAt"`
			} `json:"record"`
		} `json:"posts"`
	}
	if jerr := json.Unmarshal([]byte(body), &data); jerr != nil {
		r.Reason = "JSON parse error: " + jerr.Error()
		return r
	}
	r.Searched = true
	for _, p := range data.Posts {
		text := p.Record.Text
		matched := s.scan(text, tokens)
		if len(matched) == 0 {
			continue
		}
		title := truncateRunes(strings.ReplaceAll(strings.TrimSpace(text), "\n", " "), 120)
		if title == "" {
			title = "(no text)"
		}
		if p.Author.Handle != "" {
			title += "  @" + p.Author.Handle
		}
		web := blueskyWebURL(p.URI)
		if web == "" {
			web = p.URI
		}
		r.Hits = append(r.Hits, Hit{
			Title:        title,
			URL:          web,
			Date:         p.Record.CreatedAt,
			MatchedTerms: matched,
			Stop:         s.isStop(text),
		})
	}
	r.Status = statusOK
	r.Reason = fmt.Sprintf("searched %d posts; %d red-flag matches", len(data.Posts), len(r.Hits))
	return r
}

// blueskyWebURL builds a bsky.app web URL from an at:// post URI, or "" if the
// URI is not a recognizable feed post.
func blueskyWebURL(uri string) string {
	if !strings.HasPrefix(uri, "at://") || !strings.Contains(uri, "/app.bsky.feed.post/") {
		return ""
	}
	rest := strings.TrimPrefix(uri, "at://")
	did := rest
	if i := strings.Index(rest, "/"); i >= 0 {
		did = rest[:i]
	}
	rkey := uri[strings.LastIndex(uri, "/")+1:]
	return "https://bsky.app/profile/" + did + "/post/" + rkey
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func orUntitled(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(untitled)"
	}
	return s
}

// containsClass reports whether a space-separated HTML class attribute contains
// the exact class name.
func containsClass(classAttr, name string) bool {
	for _, c := range strings.Fields(classAttr) {
		if c == name {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------------- //
// Rendering
// ------------------------------------------------------------------------- //

// markerForForum returns the row marker for a forum result.
func markerForForum(r Result) string {
	if r.Status != statusOK {
		return markUnchk
	}
	for _, h := range r.Hits {
		if h.Stop {
			return markFlag
		}
	}
	for _, h := range r.Hits {
		if len(h.MatchedTerms) > 0 {
			return markWarn
		}
	}
	return markOK
}

// Render writes the human-readable forum-scan report to w, including the honest
// framing (absence of hits ≠ safety; unchecked forums are named; FLAG =
// investigate, not auto-block) and the FIELD-TEST / pre-audit qualifier.
func Render(w io.Writer, agg Aggregate, target string) {
	bar := strings.Repeat("=", 72)
	dash := strings.Repeat("-", 72)
	fmt.Fprintln(w, bar)
	fmt.Fprintf(w, "DSPC Gate 4b -- Community Forum Scan for: %s\n", target)
	fmt.Fprintln(w, "FIELD-TEST (v0.2.0, pre-audit): --forums is a NEW, ADVISORY capability pending")
	fmt.Fprintln(w, "its formal external security pentest (PH-2b). It makes OUTBOUND HTTP to 5 public")
	fmt.Fprintln(w, "forums (the rest of PenRUSH stays offline). Absence of hits is NOT proof of")
	fmt.Fprintln(w, "safety; unchecked forums are named below. A FLAG means INVESTIGATE -- it does")
	fmt.Fprintln(w, "NOT auto-block the install.")
	fmt.Fprintln(w, bar)
	fmt.Fprintf(w, "%-5s %-20s %-5s STATUS / REASON\n", "MARK", "FORUM", "HITS")
	fmt.Fprintln(w, dash)
	for _, r := range agg.Forums {
		mark := markerForForum(r)
		forum := truncateRunes(r.Forum, 20)
		status := "UNCHECKED -- " + r.Reason
		if r.Status == statusOK {
			status = "ok -- " + r.Reason
		}
		fmt.Fprintf(w, "%-5s %-20s %-5d %s\n", mark, forum, len(r.Hits), status)
	}

	// Detail lines for WARN/FLAG hits.
	printedHeader := false
	for _, r := range agg.Forums {
		for _, h := range r.Hits {
			if len(h.MatchedTerms) == 0 {
				continue
			}
			if !printedHeader {
				fmt.Fprintln(w, dash)
				fmt.Fprintln(w, "RED-FLAG HIT DETAIL:")
				printedHeader = true
			}
			mk := markWarn
			if h.Stop {
				mk = markFlag
			}
			fmt.Fprintf(w, "  %s [%s] %s\n", mk, r.Forum, h.Title)
			date := h.Date
			if date == "" {
				date = "-"
			}
			fmt.Fprintf(w, "       date=%s | terms=%s\n", date, strings.Join(h.MatchedTerms, ","))
			if h.URL != "" {
				fmt.Fprintf(w, "       %s\n", h.URL)
			}
		}
	}

	fmt.Fprintln(w, dash)
	uncheckedNames := "none"
	if len(agg.Unchecked) > 0 {
		names := make([]string, 0, len(agg.Unchecked))
		for _, u := range agg.Unchecked {
			names = append(names, u.Forum)
		}
		uncheckedNames = strings.Join(names, ", ")
	}
	note := ""
	if agg.Note != "" {
		note = "  [" + agg.Note + "]"
	}
	fmt.Fprintf(w, "AGGREGATE: %s  (searched: %d, unchecked: %s)%s\n",
		agg.Verdict, agg.SearchedCount, uncheckedNames, note)
	fmt.Fprintln(w, bar)
}
