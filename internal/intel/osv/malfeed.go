package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// MalFeed source: OSV.dev has no dedicated small "malicious-packages only"
// bulk export — only a 600MB+ all-ecosystems dump and 200MB+ per-ecosystem
// dumps, both too large to fetch hourly. The real source is the git
// repository OSV's own advisory `source` field points at:
// https://github.com/ossf/malicious-packages
// (osv/malicious/<ecosystem>/<pkg>/MAL-*.json).
//
// Walked via the commits-list endpoint
// (/repos/{owner}/{repo}/commits?path=...&since=...), which paginates
// properly via `page`/`per_page` with no fixed truncation, plus one
// per-commit files lookup (/repos/{owner}/{repo}/commits/{sha}) for each new
// commit — NOT GitHub's compare API (/compare/{base}...{head}), which
// hard-truncates its commits/files arrays at 250/300 regardless of the true
// range size and anchors the truncated window at the NEWER end, so indexing
// into it can never yield a commit near the oldest unprocessed change.
// One per-commit file list can still exceed GitHub's per-request cap, but
// unlike the compare API, this Link-header-paginates past it (see
// commitFiles) — on the real repo a meaningful fraction of recent commits to
// osv/malicious exceeded 300 files, so this is a real, common
// case, not an edge case, and skipping it would silently drop advisories on
// a sizeable fraction of runs.
const (
	malFeedOwner = "ossf"
	malFeedRepo  = "malicious-packages"
	// malFeedHTTPTimeout: each call here is either metadata (a commits-list
	// page, or one page of one commit's own file list) or one small advisory
	// file — nothing close to osvInterval's 45m bulk-batch timeout.
	malFeedHTTPTimeout = 30 * time.Second
	// malFeedMaxCommitsPerRun bounds one run's fetch fan-out. Each commit
	// costs at least one api.github.com call (its own file list, more if
	// paginated past 300 files) — the rate-limit-relevant cost, unlike the
	// raw-content fetches (which don't count against the api.github.com
	// quota at all).
	//
	// Sized for the UNAUTHENTICATED 60-req/hour ceiling (NewMalFeedClient's
	// token is optional): worst case this constant, plus up to
	// malFeedMaxListingPages listing calls, plus 1 commitDate call, must fit
	// under 60 with real margin — 25 + 20 + 1 = 46, leaving 14 of margin for
	// other cluster processes sharing the egress IP and for any commit whose
	// files paginate past page 1. Set GITHUB_MALFEED_TOKEN (raises the limit
	// to 5000/hour) for faster catch-up after a large backlog.
	malFeedMaxCommitsPerRun = 25
	// malFeedMaxListingPages bounds how many pages of the commits-list
	// endpoint one run will walk while enumerating what's new since the
	// watermark (100 commits/page). The endpoint returns newest-first, so
	// this window is anchored at HEAD, not at the watermark: a backlog
	// bigger than malFeedMaxListingPages*malFeedListingPerPage commits means
	// the oldest ones in that backlog fall OUTSIDE this run's enumeration
	// entirely, and the oldest malFeedMaxCommitsPerRun of what WAS enumerated
	// (near the window's far edge, not the true oldest pending commit) get
	// processed and the watermark jumps forward past everything this run
	// never saw — a real, if rare, gap; it does NOT narrow toward the true
	// oldest every run. Reaching it needs a very large backlog at this public
	// repo's typical commit rate; accepted as a bounded, rare limitation
	// rather than fixed with a forward-walking (until=) redesign.
	malFeedMaxListingPages = 20
	malFeedListingPerPage  = 100
	// malFeedMaxCommitFilePages bounds one commit's own file-list pagination
	// (see commitFiles) at 10 pages of 300 — GitHub's documented ceiling for
	// per-commit file-list pagination is 3000 files, matching this exactly.
	// No real commit in this repo's history approaches it; this exists as a
	// backstop, not an expected path.
	malFeedMaxCommitFilePages = 10
	// malFeedFetchConcurrency bounds the raw.githubusercontent.com fan-out in
	// FetchSince. Those calls don't count against the api.github.com rate
	// limit, but they DO cost real wall-clock time — a backlog-catch-up run
	// with one large commit can take minutes fetching sequentially, risking
	// MalFeedWorker's 5-minute Timeout on a bigger backlog. Same
	// bounded-concurrency shape as regionConcurrency
	// (internal/collect/aws/aws.go) and s3BucketConcurrency (aws/s3.go).
	malFeedFetchConcurrency = 8
)

// malFeedRecordPath matches an advisory JSON file under osv/malicious/ —
// osv/malicious/<ecosystem>/<package>/<MAL-id>.json. Anything else in that
// tree (README.md, .id-allocator) or outside it is not a record.
var malFeedRecordPath = regexp.MustCompile(`^osv/malicious/[^/]+/[^/]+/MAL-[^/]+\.json$`)

// MalRecord is one advisory, reduced to what the mal-feed job's inventory
// diff needs: which exact package versions it names, plus the same Vuln
// shape supplyChainFinding (internal/jobs/osv.go) already knows how to turn
// into a finding.
type MalRecord struct {
	// Affected lists every (ecosystem, name, version) this record's affected[]
	// section names — malicious-packages records pin exact versions rather
	// than ranges, since "which release is hostile" is a fact, not a range.
	Affected []Package
	Vuln     Vuln
}

// MalFeedClient walks the ossf/malicious-packages repository's commit history
// incrementally via GitHub's REST API.
type MalFeedClient struct {
	client *http.Client
	// token is an optional GitHub token (env GITHUB_MALFEED_TOKEN) to raise
	// the rate limit above the unauthenticated 60 req/hour. See
	// malFeedMaxCommitsPerRun's doc for the budget this constant is sized
	// against.
	token string
}

// NewMalFeedClient builds a client. token may be empty (unauthenticated).
// safenet.New, not http.DefaultClient, per house SSRF-blocking convention —
// mirrors Client's own construction in osv.go for the same external-API shape.
func NewMalFeedClient(token string) *MalFeedClient {
	return &MalFeedClient{client: safenet.New(malFeedHTTPTimeout), token: token}
}

// FetchSince returns every malicious-package advisory added or modified in
// ossf/malicious-packages since lastSHA, plus the SHA the caller should
// persist as the new watermark.
//
// The returned SHA is NOT always the repository's current HEAD: when more
// than malFeedMaxCommitsPerRun commits changed since lastSHA, this processes
// only the oldest malFeedMaxCommitsPerRun of them and returns THAT commit's
// SHA instead. Returning full HEAD while only having processed a prefix of
// the range would silently and permanently drop the unprocessed remainder —
// the next run's base would already be past it. Returning the exact SHA of
// the last commit actually processed means the remainder is still ahead of
// the watermark and gets picked up on a later run.
//
// lastSHA == "" is the cold-start case: rather than walking the entire
// repository history (which would re-download years of records this
// same-session's daily refresh_osv sweep already discovers through the
// ordinary per-package OSV query — MAL-* advisories are ordinary OSV records,
// returned by /v1/querybatch like any CVE), this
// just resolves and returns HEAD with zero records. The fast-path value of
// this job is catching NEW advisories quickly, not backfilling history the
// slower daily sweep already covers.
//
// A single malformed advisory file, or one commit whose own file list
// couldn't be fetched, is logged and skipped, mirroring hydrate's
// partial-failure posture in osv.go — the run degrades rather than losing
// every record in it.
func (c *MalFeedClient) FetchSince(ctx context.Context, lastSHA string) (records []MalRecord, watermark string, err error) {
	if lastSHA == "" {
		head, err := c.headSHA(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("FetchSince: %w", err)
		}
		return nil, head, nil // cold start: seed the watermark, no backfill
	}

	logger := log.FromContext(ctx)

	since, err := c.commitDate(ctx, lastSHA)
	if err != nil {
		return nil, "", fmt.Errorf("FetchSince: %w", err)
	}
	commits, err := c.listCommitsSince(ctx, since, lastSHA)
	if err != nil {
		return nil, "", fmt.Errorf("FetchSince: %w", err)
	}
	if len(commits) == 0 {
		return nil, lastSHA, nil // nothing under osv/malicious/ changed since last run — watermark unchanged
	}

	if len(commits) > malFeedMaxCommitsPerRun {
		logger.Warn().Int("commits_found", len(commits)).Int("limit", malFeedMaxCommitsPerRun).
			Msg("osv malfeed: more commits changed than this run's cap — processing the oldest slice, remainder caught on a later run")
		commits = commits[:malFeedMaxCommitsPerRun] // commits is oldest-first; see listCommitsSince
	}
	newWatermark := commits[len(commits)-1]

	seen := map[string]bool{}
	var files []string
	for _, sha := range commits {
		fs, err := c.commitFiles(ctx, sha)
		if err != nil {
			logger.Warn().Err(err).Str("commit", sha).Msg("osv malfeed: could not list a commit's files, skipped")
			continue
		}
		for _, f := range fs {
			if !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
		}
	}

	// Raw-content fetches don't count against the api.github.com rate limit
	// (raw.githubusercontent.com is a separate, unmetered CDN), but they DO
	// cost real wall-clock time sequentially: a capped run recovering from a
	// backlog that includes one large (hundreds-of-files) commit can take
	// minutes fetched one at a time, risking MalFeedWorker's 5-minute Timeout
	// on a bigger backlog. Fanned out the same bounded way regionConcurrency
	// (internal/collect/aws/aws.go) and s3BucketConcurrency (aws/s3.go)
	// already fan out their own independent per-item calls.
	out := make([]MalRecord, 0, len(files))
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, malFeedFetchConcurrency)
	)
	for _, f := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error().Any("panic", rec).Str("mal_feed_entry", path).
						Msg("osv malfeed: fetch panicked; entry skipped")
				}
			}()
			rec, err := c.fetchRecord(ctx, path, newWatermark)
			if err != nil {
				logger.Warn().Err(err).Str("mal_feed_entry", path).Msg("osv malfeed: entry skipped, malformed or unfetchable")
				return
			}
			mu.Lock()
			out = append(out, rec)
			mu.Unlock()
		}(f)
	}
	wg.Wait()
	return out, newWatermark, nil
}

func (c *MalFeedClient) authedRequest(ctx context.Context, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return req, nil
}

func (c *MalFeedClient) headSHA(ctx context.Context) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/main", malFeedOwner, malFeedRepo)
	req, err := c.authedRequest(ctx, url)
	if err != nil {
		return "", fmt.Errorf("headSHA: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("headSHA: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("headSHA: unexpected status %d", resp.StatusCode)
	}
	var body struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("headSHA: decode: %w", err)
	}
	if body.SHA == "" {
		return "", fmt.Errorf("headSHA: empty sha in response")
	}
	return body.SHA, nil
}

// commitDate returns one commit's committer date, in the exact form GitHub's
// commits-list `since` filter needs — the anchor listCommitsSince walks
// forward from.
func (c *MalFeedClient) commitDate(ctx context.Context, sha string) (time.Time, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", malFeedOwner, malFeedRepo, sha)
	req, err := c.authedRequest(ctx, url)
	if err != nil {
		return time.Time{}, fmt.Errorf("commitDate: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("commitDate: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("commitDate %s: unexpected status %d", sha, resp.StatusCode)
	}
	var body struct {
		Commit struct {
			Committer struct {
				Date time.Time `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return time.Time{}, fmt.Errorf("commitDate %s: decode: %w", sha, err)
	}
	if body.Commit.Committer.Date.IsZero() {
		return time.Time{}, fmt.Errorf("commitDate %s: empty committer date in response", sha)
	}
	return body.Commit.Committer.Date, nil
}

// listCommitsSince returns every commit touching osv/malicious/ strictly
// after `since`, OLDEST FIRST, via GitHub's commits-list endpoint —
// paginated with `page`/`per_page`, not the compare API's fixed-size
// truncated arrays (see this file's top-level doc for why compare doesn't
// work here). GitHub returns this endpoint's pages newest-first, so the
// LAST page fetched holds the oldest results; this walks pages front to
// back up to malFeedMaxListingPages, then reverses the concatenated result.
//
// excludeSHA filters out the watermark commit itself, defensively — `since`
// is documented as "commits after this date," but a same-timestamp edge case
// should never re-surface the commit FetchSince was already called with.
func (c *MalFeedClient) listCommitsSince(ctx context.Context, since time.Time, excludeSHA string) ([]string, error) {
	var newestFirst []string
	for page := 1; page <= malFeedMaxListingPages; page++ {
		url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?path=osv/malicious&since=%s&per_page=%d&page=%d",
			malFeedOwner, malFeedRepo, since.UTC().Format(time.RFC3339), malFeedListingPerPage, page)
		req, err := c.authedRequest(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("listCommitsSince: %w", err)
		}
		resp, err := c.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("listCommitsSince: %w", err)
		}
		var pageCommits []struct {
			SHA string `json:"sha"`
		}
		decodeErr := json.NewDecoder(resp.Body).Decode(&pageCommits)
		status := resp.StatusCode
		_ = resp.Body.Close()
		if status != http.StatusOK {
			return nil, fmt.Errorf("listCommitsSince: unexpected status %d (page %d)", status, page)
		}
		if decodeErr != nil {
			return nil, fmt.Errorf("listCommitsSince: decode (page %d): %w", page, decodeErr)
		}
		for _, cm := range pageCommits {
			if cm.SHA != excludeSHA {
				newestFirst = append(newestFirst, cm.SHA)
			}
		}
		if len(pageCommits) < malFeedListingPerPage {
			break // short page: this was the last one
		}
		if page == malFeedMaxListingPages {
			log.FromContext(ctx).Warn().Int("pages", page).
				Msg("osv malfeed: commit backlog exceeds the listing-page ceiling — processing what this run could enumerate, remainder narrows on later runs")
		}
	}

	oldestFirst := make([]string, len(newestFirst))
	for i, sha := range newestFirst {
		oldestFirst[len(newestFirst)-1-i] = sha
	}
	return oldestFirst, nil
}

// commitFiles returns one commit's own osv/malicious/ advisory file changes
// (added/modified, not removed) — the per-commit equivalent of what the
// compare API would return in bulk for an entire range at once.
// commitFiles walks a single commit's own file list, following the `Link:
// rel="next"` response header GitHub sends when one commit's diff exceeds
// 300 files — a real, non-rare case for this public repo, whose bulk-import
// commits routinely exceed 300 files, so stopping at the first page would
// silently drop advisory files. GitHub
// documents per-commit file-list pagination
// continuing up to 3000 files; malFeedMaxCommitFilePages bounds this at that
// same ceiling (10 pages × 300) with a loud warning if even that is
// exceeded — no commit in this repo's history comes anywhere near it.
func (c *MalFeedClient) commitFiles(ctx context.Context, sha string) ([]string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", malFeedOwner, malFeedRepo, sha)
	var out []string
	for page := 1; url != ""; page++ {
		if page > malFeedMaxCommitFilePages {
			log.FromContext(ctx).Warn().Str("commit", sha).Int("pages", page-1).
				Msg("osv malfeed: a single commit's file list exceeds this client's pagination ceiling — remainder skipped")
			break
		}
		req, err := c.authedRequest(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("commitFiles: %w", err)
		}
		resp, err := c.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("commitFiles: %w", err)
		}
		var body struct {
			Files []struct {
				Filename string `json:"filename"`
				Status   string `json:"status"`
			} `json:"files"`
		}
		decodeErr := json.NewDecoder(resp.Body).Decode(&body)
		status := resp.StatusCode
		next := nextPageLink(resp.Header.Get("Link"))
		_ = resp.Body.Close()
		if status != http.StatusOK {
			return nil, fmt.Errorf("commitFiles %s: unexpected status %d (page %d)", sha, status, page)
		}
		if decodeErr != nil {
			return nil, fmt.Errorf("commitFiles %s: decode (page %d): %w", sha, page, decodeErr)
		}
		for _, f := range body.Files {
			if f.Status == "removed" {
				continue // a withdrawn/renamed record — resolution is refresh_osv's job, not this one's
			}
			if malFeedRecordPath.MatchString(f.Filename) {
				out = append(out, f.Filename)
			}
		}
		url = next
	}
	return out, nil
}

// nextPageLink extracts the rel="next" URL from an RFC 5988 Link header, or
// "" if there is none (the common case: no more pages). GitHub's exact
// format: `<https://...&page=2>; rel="next", <https://...>; rel="last"`.
func nextPageLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		start := strings.IndexByte(part, '<')
		end := strings.IndexByte(part, '>')
		if start < 0 || end < 0 || end <= start {
			continue
		}
		return part[start+1 : end]
	}
	return ""
}

// fetchRecord downloads and decodes one advisory file at the given commit
// (pinned to a specific SHA, never "main", so the content can never move
// mid-run).
func (c *MalFeedClient) fetchRecord(ctx context.Context, path, atSHA string) (MalRecord, error) {
	url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", malFeedOwner, malFeedRepo, atSHA, path)
	req, err := c.authedRequest(ctx, url)
	if err != nil {
		return MalRecord{}, fmt.Errorf("fetchRecord: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return MalRecord{}, fmt.Errorf("fetchRecord: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return MalRecord{}, fmt.Errorf("fetchRecord %s: unexpected status %d", path, resp.StatusCode)
	}
	return decodeMalRecord(path, resp.Body)
}

// decodeMalRecord parses one advisory JSON body. Shape mirrors getVuln's
// decode in osv.go, plus affected[].versions — the query/vulns API doesn't
// need that field (a query is already scoped to one package), but this diff
// has no query to scope it, so it needs the exact version list itself.
func decodeMalRecord(path string, body io.Reader) (MalRecord, error) {
	var raw struct {
		ID       string   `json:"id"`
		Aliases  []string `json:"aliases"`
		Upstream []string `json:"upstream"`
		Summary  string   `json:"summary"`
		Details  string   `json:"details"`
		Affected []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Versions []string `json:"versions"`
		} `json:"affected"`
		Severity         []severity `json:"severity"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	}
	if err := json.NewDecoder(body).Decode(&raw); err != nil {
		return MalRecord{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if raw.ID == "" {
		return MalRecord{}, fmt.Errorf("%s: missing id", path)
	}
	if !strings.HasPrefix(raw.ID, "MAL-") {
		return MalRecord{}, fmt.Errorf("%s: id %q is not a MAL- advisory", path, raw.ID)
	}

	var affected []Package
	for _, a := range raw.Affected {
		for _, v := range a.Versions {
			affected = append(affected, Package{
				Ecosystem: a.Package.Ecosystem,
				Name:      a.Package.Name,
				Version:   v,
			})
		}
	}

	return MalRecord{
		Affected: affected,
		Vuln: Vuln{
			ID:       raw.ID,
			Aliases:  raw.Aliases,
			Upstream: raw.Upstream,
			Summary:  raw.Summary,
			Details:  raw.Details,
			// Every record under osv/malicious/ is by definition a MAL-*
			// advisory, so resolveSeverity's IsMalicious branch always wins —
			// same SeverityCritical resolveSeverity gives a MAL-* advisory
			// fetched through the ordinary per-package query path.
			Severity: resolveSeverity(raw.ID, raw.DatabaseSpecific.Severity, raw.Severity),
			// affected (FixedVersion's lookup table) is deliberately left
			// empty: a malicious package has no fixed version, and
			// supplyChainFinding overrides the remediation text for any
			// osv.IsMalicious advisory regardless of what FixedVersion would
			// have returned.
		},
	}, nil
}
