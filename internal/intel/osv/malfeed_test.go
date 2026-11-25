package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// fakeGitHub serves the endpoints MalFeedClient calls: HEAD commit, a single
// commit's date+files, the paginated commits-list, and raw content — enough
// to drive FetchSince end-to-end against a scripted repo history without
// touching the real network.
type fakeGitHub struct {
	headSHA string
	// commits maps sha -> its date+files, for both the per-commit lookup
	// (commitDate/commitFiles) and the listing endpoint's filter/sort.
	commits map[string]commitFixture
	// raw maps "sha/path" to the raw file content served for it.
	raw map[string]string
}

type commitFixture struct {
	Date  time.Time
	Files []compareFileFixture
}

type compareFileFixture struct {
	Filename string
	Status   string
}

func (f *fakeGitHub) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// Listing endpoint: GET /repos/.../commits?path=...&since=...&per_page=...&page=...
	mux.HandleFunc("GET /repos/ossf/malicious-packages/commits", func(w http.ResponseWriter, r *http.Request) {
		sinceStr := r.URL.Query().Get("since")
		since, err := time.Parse(time.RFC3339, sinceStr)
		require.NoError(t, err)
		perPage := 100
		page := 1
		if v := r.URL.Query().Get("per_page"); v != "" {
			fmt.Sscanf(v, "%d", &perPage)
		}
		if v := r.URL.Query().Get("page"); v != "" {
			fmt.Sscanf(v, "%d", &page)
		}

		type shaDate struct {
			sha  string
			date time.Time
		}
		var matched []shaDate
		for sha, cf := range f.commits {
			if cf.Date.After(since) {
				matched = append(matched, shaDate{sha, cf.Date})
			}
		}
		sort.Slice(matched, func(i, j int) bool { return matched[i].date.After(matched[j].date) }) // newest first, matches real API

		start := (page - 1) * perPage
		end := start + perPage
		if start > len(matched) {
			start = len(matched)
		}
		if end > len(matched) {
			end = len(matched)
		}
		pageSlice := matched[start:end]

		var body []map[string]string
		for _, sd := range pageSlice {
			body = append(body, map[string]string{"sha": sd.sha})
		}
		_ = json.NewEncoder(w).Encode(body)
	})

	// Single commit / HEAD lookup: GET /repos/.../commits/{ref}[?filepage=N].
	// filepage simulates GitHub's real per-commit file-list pagination (which
	// this fixture cannot express via a page-size fixture field cleanly, so
	// it hardcodes the real 300-per-page boundary — the exact value that
	// matters, since that's GitHub's actual ceiling this test exists to
	// exercise pagination past).
	const realGitHubFilesPerPage = 300
	mux.HandleFunc("GET /repos/ossf/malicious-packages/commits/{ref}", func(w http.ResponseWriter, r *http.Request) {
		ref := r.PathValue("ref")
		if ref == "main" {
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": f.headSHA})
			return
		}
		cf, ok := f.commits[ref]
		if !ok {
			http.NotFound(w, r)
			return
		}
		filePage := 1
		if v := r.URL.Query().Get("filepage"); v != "" {
			fmt.Sscanf(v, "%d", &filePage)
		}
		start := (filePage - 1) * realGitHubFilesPerPage
		end := start + realGitHubFilesPerPage
		if start > len(cf.Files) {
			start = len(cf.Files)
		}
		if end > len(cf.Files) {
			end = len(cf.Files)
		}
		if end < len(cf.Files) {
			// Absolute URL, matching real GitHub's Link header shape — the
			// client re-issues this exact URL on its next iteration, and it
			// must round-trip back through rewriteHostTransport the same way
			// the initial request did.
			w.Header().Set("Link", fmt.Sprintf(`<https://api.github.com%s?filepage=%d>; rel="next"`, r.URL.Path, filePage+1))
		}
		var body struct {
			Commit struct {
				Committer struct {
					Date time.Time `json:"date"`
				} `json:"committer"`
			} `json:"commit"`
			Files []map[string]string `json:"files"`
		}
		body.Commit.Committer.Date = cf.Date
		for _, cff := range cf.Files[start:end] {
			body.Files = append(body.Files, map[string]string{"filename": cff.Filename, "status": cff.Status})
		}
		_ = json.NewEncoder(w).Encode(body)
	})

	mux.HandleFunc("/ossf/malicious-packages/", func(w http.ResponseWriter, r *http.Request) {
		// raw.githubusercontent.com path shape: /owner/repo/sha/path. f.raw is
		// keyed by PATH ONLY (not sha/path): a file added at one commit is
		// still fetchable, byte-identical, at any LATER commit pinned by
		// fetchRecord — exactly like the real repo — so the fixture doesn't
		// need one raw entry per (introducing-sha, later-pin-sha) pair.
		path := r.URL.Path[len("/ossf/malicious-packages/"):]
		if i := strings.IndexByte(path, '/'); i >= 0 {
			path = path[i+1:] // strip the leading sha segment
		}
		content, ok := f.raw[path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, content)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newTestMalFeedClient points a client at the fake server for BOTH the
// api.github.com and raw.githubusercontent.com hosts it needs, by overriding
// the URLs built from malFeedOwner/malFeedRepo constants — done here via a
// client whose http.Client transport rewrites those two real hosts to the
// fake server, since MalFeedClient hardcodes the real hostnames (mirrors
// production exactly; only the transport is swapped in tests, the same way
// osv_test.go's newTestClient swaps baseURL — this package's OSV Client has a
// baseURL field to override, MalFeedClient does not because it targets two
// distinct real hosts, not one, so a transport-level redirect is the
// equivalent seam).
func newTestMalFeedClient(t *testing.T, srv *httptest.Server) *MalFeedClient {
	t.Helper()
	c := NewMalFeedClient("")
	c.client = &http.Client{Transport: rewriteHostTransport{
		to: srv.URL,
		from: map[string]bool{
			"api.github.com":            true,
			"raw.githubusercontent.com": true,
		},
	}}
	return c
}

// rewriteHostTransport redirects requests to any host in `from` to `to`,
// preserving path/query — a test-only seam so MalFeedClient's real,
// hardcoded external hostnames can be exercised against a local fixture
// server without changing production code shape.
type rewriteHostTransport struct {
	to   string
	from map[string]bool
}

func (t rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.from[req.URL.Host] {
		return http.DefaultTransport.RoundTrip(req)
	}
	newURL := t.to + req.URL.Path
	if req.URL.RawQuery != "" {
		newURL += "?" + req.URL.RawQuery
	}
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header
	return http.DefaultTransport.RoundTrip(newReq)
}

const keyvMalRecord = `{
	"id": "MAL-2026-11524",
	"summary": "Malicious code in keyv (npm)",
	"details": "trojanized preinstall hook",
	"affected": [{
		"package": {"ecosystem": "npm", "name": "keyv"},
		"versions": ["6.0.0"]
	}]
}`

const cacheableMalRecord = `{
	"id": "MAL-2026-11963",
	"summary": "Malicious code in cacheable (npm)",
	"affected": [{
		"package": {"ecosystem": "npm", "name": "cacheable"},
		"versions": ["2.5.1", "2.5.2"]
	}]
}`

var t0 = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

func TestMalFeedClient_FetchSince_ColdStartSeedsWatermarkNoBackfill(t *testing.T) {
	gh := &fakeGitHub{headSHA: "head1"}
	c := newTestMalFeedClient(t, gh.server(t))

	records, head, err := c.FetchSince(context.Background(), "")
	require.NoError(t, err)
	require.Empty(t, records, "cold start must not backfill — the daily refresh_osv sweep already covers existing MAL-* advisories")
	require.Equal(t, "head1", head)
}

func TestMalFeedClient_FetchSince_NoChangeIsNoop(t *testing.T) {
	gh := &fakeGitHub{
		commits: map[string]commitFixture{"old": {Date: t0}},
	}
	c := newTestMalFeedClient(t, gh.server(t))

	records, head, err := c.FetchSince(context.Background(), "old")
	require.NoError(t, err)
	require.Empty(t, records)
	require.Equal(t, "old", head, "no new commits under osv/malicious/ since the watermark — watermark stays put")
}

func TestMalFeedClient_FetchSince_FetchesNewRecordsOnly(t *testing.T) {
	gh := &fakeGitHub{
		commits: map[string]commitFixture{
			"old": {Date: t0},
			"c1": {Date: t0.Add(1 * time.Hour), Files: []compareFileFixture{
				{Filename: "osv/malicious/npm/keyv/MAL-2026-11524.json", Status: "added"},
			}},
			"head2": {Date: t0.Add(2 * time.Hour), Files: []compareFileFixture{
				{Filename: "osv/malicious/npm/cacheable/MAL-2026-11963.json", Status: "added"},
				{Filename: "osv/malicious/README.md", Status: "modified"},                  // not a record path — skipped
				{Filename: "osv/malicious/npm/old-pkg/MAL-2020-1.json", Status: "removed"}, // removed — skipped
			}},
		},
		raw: map[string]string{
			"osv/malicious/npm/keyv/MAL-2026-11524.json":      keyvMalRecord,
			"osv/malicious/npm/cacheable/MAL-2026-11963.json": cacheableMalRecord,
		},
	}
	c := newTestMalFeedClient(t, gh.server(t))

	records, head, err := c.FetchSince(context.Background(), "old")
	require.NoError(t, err)
	require.Equal(t, "head2", head, "watermark advances to the newest (last-processed) commit")
	require.Len(t, records, 2)

	byID := map[string]MalRecord{}
	for _, r := range records {
		byID[r.Vuln.ID] = r
	}
	keyv, ok := byID["MAL-2026-11524"]
	require.True(t, ok)
	require.Equal(t, finding.SeverityCritical, keyv.Vuln.Severity, "every malicious/ record is critical by construction")
	require.Equal(t, []Package{{Ecosystem: "npm", Name: "keyv", Version: "6.0.0"}}, keyv.Affected)

	cacheable, ok := byID["MAL-2026-11963"]
	require.True(t, ok)
	require.ElementsMatch(t, []Package{
		{Ecosystem: "npm", Name: "cacheable", Version: "2.5.1"},
		{Ecosystem: "npm", Name: "cacheable", Version: "2.5.2"},
	}, cacheable.Affected)
}

// TestMalFeedClient_FetchSince_SkipsMalformedEntry mirrors hydrate's
// partial-failure test: one corrupt advisory file among valid ones must not
// fail the whole run — the valid ones still come back, the corrupt one is
// logged and skipped.
func TestMalFeedClient_FetchSince_SkipsMalformedEntry(t *testing.T) {
	gh := &fakeGitHub{
		commits: map[string]commitFixture{
			"old": {Date: t0},
			"head3": {Date: t0.Add(1 * time.Hour), Files: []compareFileFixture{
				{Filename: "osv/malicious/npm/keyv/MAL-2026-11524.json", Status: "added"},
				{Filename: "osv/malicious/npm/corrupt/MAL-2026-9999.json", Status: "added"},
			}},
		},
		raw: map[string]string{
			"osv/malicious/npm/keyv/MAL-2026-11524.json":   keyvMalRecord,
			"osv/malicious/npm/corrupt/MAL-2026-9999.json": `{not valid json`,
		},
	}
	c := newTestMalFeedClient(t, gh.server(t))

	records, head, err := c.FetchSince(context.Background(), "old")
	require.NoError(t, err)
	require.Equal(t, "head3", head)
	require.Len(t, records, 1)
	require.Equal(t, "MAL-2026-11524", records[0].Vuln.ID)
}

func TestMalFeedClient_FetchSince_CommitDateErrorPropagates(t *testing.T) {
	gh := &fakeGitHub{commits: map[string]commitFixture{}} // "old" not found -> 404
	c := newTestMalFeedClient(t, gh.server(t))

	_, _, err := c.FetchSince(context.Background(), "old")
	require.Error(t, err)
}

// TestMalFeedClient_FetchSince_MaxCommitsPerRunCap_RemainderCaughtNextRun is
// the direct regression test for a bug: a capped run must
// return the SHA of the last commit it actually processed (not the newest
// commit found), so the remainder is still ahead of the watermark and a
// SECOND FetchSince call — simulating the next hourly run — reaches it,
// rather than the remainder being silently and permanently dropped.
func TestMalFeedClient_FetchSince_MaxCommitsPerRunCap_RemainderCaughtNextRun(t *testing.T) {
	total := malFeedMaxCommitsPerRun + 5
	commits := map[string]commitFixture{"old": {Date: t0}}
	raw := map[string]string{}
	var shas []string
	for i := 0; i < total; i++ {
		sha := fmt.Sprintf("c%d", i)
		shas = append(shas, sha)
		path := fmt.Sprintf("osv/malicious/npm/pkg%d/MAL-2026-%d.json", i, i)
		commits[sha] = commitFixture{
			Date:  t0.Add(time.Duration(i+1) * time.Hour),
			Files: []compareFileFixture{{Filename: path, Status: "added"}},
		}
		content := fmt.Sprintf(`{"id":"MAL-2026-%d","affected":[{"package":{"ecosystem":"npm","name":"pkg%d"},"versions":["1.0.0"]}]}`, i, i)
		raw[path] = content
	}
	gh := &fakeGitHub{commits: commits, raw: raw}
	c := newTestMalFeedClient(t, gh.server(t))

	// Run 1: capped at malFeedMaxCommitsPerRun (oldest-first), watermark must
	// be the cap-th commit, not the newest one found.
	records1, watermark1, err := c.FetchSince(context.Background(), "old")
	require.NoError(t, err)
	require.Len(t, records1, malFeedMaxCommitsPerRun, "must stop at the explicit per-run cap")
	require.Equal(t, shas[malFeedMaxCommitsPerRun-1], watermark1, "watermark must be the last commit actually processed, not the newest one found")

	// Run 2 ("next hour"): starting from run 1's watermark must reach the
	// remaining commits — the exact regression this test exists to pin.
	records2, watermark2, err := c.FetchSince(context.Background(), watermark1)
	require.NoError(t, err)
	require.Len(t, records2, 5, "the capped remainder must be caught on the next run, not lost")
	require.Equal(t, shas[total-1], watermark2)

	seen := map[string]bool{}
	for _, r := range append(records1, records2...) {
		seen[r.Vuln.ID] = true
	}
	require.Len(t, seen, total, "across both runs every record must be seen exactly once, none dropped")
}

// TestMalFeedClient_FetchSince_OneCommitTouchingManyFiles is the direct
// regression test for a design flaw in an earlier revision of
// this file: GitHub's compare API truncates its FILES array at 300 far
// sooner than its commits array (observed against the real repo: a few dozen
// commits was enough to hit the 300-file cap, since commits there average
// ~8 files each with occasional bulk-import commits touching far more) — a
// cap sized only against commit count did nothing to protect against that.
// This design instead fetches each commit's OWN file list individually, so
// one commit touching many files only risks that ONE commit's own list
// being incomplete (a categorically smaller blast radius), never an entire
// range. This test exercises a single commit with several files to confirm
// all of them are still collected correctly (no per-commit truncation
// simulated here — GitHub's own per-commit cap is a separate, external
// constraint this package can't control, same posture as the top-level doc
// comment takes toward it).
func TestMalFeedClient_FetchSince_OneCommitTouchingManyFiles(t *testing.T) {
	var files []compareFileFixture
	raw := map[string]string{}
	for i := 0; i < 50; i++ {
		path := fmt.Sprintf("osv/malicious/npm/bulkpkg%d/MAL-2026-%d.json", i, i)
		files = append(files, compareFileFixture{Filename: path, Status: "added"})
		raw[path] = fmt.Sprintf(`{"id":"MAL-2026-%d","affected":[{"package":{"ecosystem":"npm","name":"bulkpkg%d"},"versions":["1.0.0"]}]}`, i, i)
	}
	gh := &fakeGitHub{
		commits: map[string]commitFixture{
			"old":  {Date: t0},
			"bulk": {Date: t0.Add(1 * time.Hour), Files: files},
		},
		raw: raw,
	}
	c := newTestMalFeedClient(t, gh.server(t))

	records, head, err := c.FetchSince(context.Background(), "old")
	require.NoError(t, err)
	require.Equal(t, "bulk", head)
	require.Len(t, records, 50, "a single bulk-import commit's files are all collected, not truncated by a cap sized against commit count")
}

// TestMalFeedClient_CommitFiles_FollowsPaginationBeyond300 is the direct
// regression test for a bug: GitHub truncates a single
// commit's file list at 300 and signals more via a `Link: rel="next"`
// response header, and a meaningful share of commits to the public
// osv/malicious tree exceed 300 files. A version of
// commitFiles that stopped at the first page silently dropped files on
// those commits. This drives a single commit with 350 files
// (past the real 300-per-page boundary the test server enforces) and
// confirms all 350 come back, not just the first 300.
func TestMalFeedClient_CommitFiles_FollowsPaginationBeyond300(t *testing.T) {
	var files []compareFileFixture
	raw := map[string]string{}
	for i := 0; i < 350; i++ {
		path := fmt.Sprintf("osv/malicious/npm/pkg%d/MAL-2026-%d.json", i, i)
		files = append(files, compareFileFixture{Filename: path, Status: "added"})
		raw[path] = fmt.Sprintf(`{"id":"MAL-2026-%d","affected":[{"package":{"ecosystem":"npm","name":"pkg%d"},"versions":["1.0.0"]}]}`, i, i)
	}
	gh := &fakeGitHub{
		commits: map[string]commitFixture{
			"old":  {Date: t0},
			"huge": {Date: t0.Add(1 * time.Hour), Files: files},
		},
		raw: raw,
	}
	c := newTestMalFeedClient(t, gh.server(t))

	records, head, err := c.FetchSince(context.Background(), "old")
	require.NoError(t, err)
	require.Equal(t, "huge", head)
	require.Len(t, records, 350, "a commit's file list must paginate past GitHub's 300-file-per-page ceiling, not silently truncate at page 1")
}

// TestMalFeedClient_ListCommitsSince_MultiPagePagination is the direct
// regression test for the listing endpoint's own pagination, which no
// existing test exercised (the largest prior fixture stayed within a single
// 100-commit page). Drives 150 commits since the watermark — more than one
// page (malFeedListingPerPage=100) — and confirms the client walks page 2
// and finds all of them, in the correct oldest-first order for the
// per-run cap to slice correctly.
func TestMalFeedClient_ListCommitsSince_MultiPagePagination(t *testing.T) {
	const total = 150
	commits := map[string]commitFixture{"old": {Date: t0}}
	raw := map[string]string{}
	var shas []string
	for i := 0; i < total; i++ {
		sha := fmt.Sprintf("c%d", i)
		shas = append(shas, sha)
		path := fmt.Sprintf("osv/malicious/npm/pkg%d/MAL-2026-%d.json", i, i)
		commits[sha] = commitFixture{
			Date:  t0.Add(time.Duration(i+1) * time.Minute),
			Files: []compareFileFixture{{Filename: path, Status: "added"}},
		}
		raw[path] = fmt.Sprintf(`{"id":"MAL-2026-%d","affected":[{"package":{"ecosystem":"npm","name":"pkg%d"},"versions":["1.0.0"]}]}`, i, i)
	}
	gh := &fakeGitHub{commits: commits, raw: raw}
	c := newTestMalFeedClient(t, gh.server(t))

	// The per-run cap (malFeedMaxCommitsPerRun, currently well under 150)
	// means one FetchSince call won't drain all 150 — but the CAP applied
	// must be against the FULL, correctly-multi-page-enumerated, oldest-first
	// list, not just whatever page 1 alone contained. Confirm the watermark
	// after one run is the cap-th OLDEST commit (shas[cap-1]), which can only
	// be correct if pagination walked far enough to know the true oldest
	// slice — page 1 alone (the 100 newest) would put the cap-th oldest
	// commit on page 2, out of a single-page implementation's reach entirely.
	_, watermark, err := c.FetchSince(context.Background(), "old")
	require.NoError(t, err)
	require.Equal(t, shas[malFeedMaxCommitsPerRun-1], watermark,
		"the cap must apply against the full multi-page-enumerated oldest-first list, not just the first page")
}
