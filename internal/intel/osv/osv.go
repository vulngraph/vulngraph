// Package osv is the OSV.dev supply-chain intel feed. OSV natively
// aggregates the GitHub Advisory Database (GHSA) plus the per-ecosystem
// databases (Go vulndb, PyPA, RustSec, …), so this one feed answers "which
// advisories affect this package version?" for the package assets the GitHub
// collector inventories. The API is keyless and unmetered; its only hard limit
// is 1000 queries per batch call.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const (
	defaultBaseURL = "https://api.osv.dev"
	httpTimeout    = 60 * time.Second
	// maxBatch is osv.dev's hard cap on queries per /v1/querybatch call.
	maxBatch = 1000
	// maxQueryPages bounds the per-batch pagination walk; a package with more
	// than maxQueryPages×1000 advisories is pathological input, not data.
	maxQueryPages = 10
	// hydrateConcurrency bounds the /v1/vulns fan-out.
	hydrateConcurrency = 8
)

// Package identifies one package version in OSV's naming: Ecosystem is the OSV
// ecosystem ("npm", "PyPI", "Maven", …) and Name follows its conventions
// (Maven "group:artifact", Go module path, scoped npm name).
type Package struct {
	Ecosystem string
	Name      string
	Version   string
}

// Vuln is one advisory, reduced to what the supply-chain feed needs.
type Vuln struct {
	ID      string
	Aliases []string
	// Upstream is OSV's link from a DISTRO advisory to the vulnerability it
	// re-publishes. Distro records (DEBIAN-CVE-*, ALPINE-CVE-*, UBUNTU-CVE-*)
	// carry NO aliases at all — the CVE lives here — so reading only Aliases
	// leaves every OS-package finding without a CVE-shaped CheckID, and both
	// the KEV match and the EPSS lookup require that prefix.
	Upstream []string
	Summary  string
	Details  string
	Severity finding.Severity

	affected []affectedPkg
}

// CVE returns the advisory's first CVE identifier (see CVEs), or "" if it has
// none. A finding takes one CHECK id per CVE (CheckIDs); this one is the alias a
// MAL-* finding keeps in its metadata for KEV and EPSS.
func (v Vuln) CVE() string {
	if cves := v.CVEs(); len(cves) > 0 {
		return cves[0]
	}
	return ""
}

// FixedVersion returns the first version that fixes this advisory for the
// given package, or "" when no fix is published. Only entries for the package's
// own release count (see targetFor): Red Hat and SUSE advisories list every
// stream's fix, and a RHEL 10 build is not the RHEL 9 host's remediation.
func (v Vuln) FixedVersion(p Package) string {
	t := targetFor(p.Ecosystem)
	fallback := ""
	for _, a := range v.affected {
		if !t.match(a.Package.Ecosystem) || a.Package.Name != p.Name {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed == "" {
					continue
				}
				// A re-checked family can list one package under several
				// streams of the release (baseos, appstream): prefer the entry
				// that actually holds the installed version.
				if !t.recheck || a.contains(p.Version) {
					return e.Fixed
				}
				if fallback == "" {
					fallback = e.Fixed
				}
			}
		}
	}
	return fallback
}

type affectedPkg struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []struct {
		Type   string       `json:"type"`
		Events []rangeEvent `json:"events"`
	} `json:"ranges"`
	Versions []string `json:"versions"`
}

type rangeEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

func (e rangeEvent) version() string {
	switch {
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	}
	return e.LastAffected
}

// Client queries the OSV.dev API.
type Client struct {
	client  *http.Client
	baseURL string
}

func NewClient() *Client {
	return &Client{client: safenet.New(httpTimeout), baseURL: defaultBaseURL}
}

// Query returns the advisories affecting each package. It batch-queries for
// advisory IDs (chunked, paginated), then hydrates each distinct ID once with
// bounded fan-out. A single advisory failing to hydrate is logged and skipped —
// the feed degrades rather than losing the whole refresh.
//
// incomplete lists packages for which at least one advisory ID failed to
// hydrate: their returned Vuln slice is a LOWER BOUND, not authoritative, so a
// caller must not infer "advisory withdrawn" from an absent entry (see the OSV
// reconcile in internal/jobs/osv.go). A package whose ecosystem OSV does not
// serve is never sent — one such query fails the whole batch — and is reported
// incomplete with no advisories: unqueried, not clean.
func (c *Client) Query(ctx context.Context, pkgs []Package) (result map[Package][]Vuln, incomplete map[Package]bool, err error) {
	incomplete = map[Package]bool{}
	queryable := make([]Package, 0, len(pkgs))
	for _, p := range pkgs {
		if Supported(p.Ecosystem) {
			queryable = append(queryable, p)
		} else {
			incomplete[p] = true
		}
	}
	if skipped := len(pkgs) - len(queryable); skipped > 0 {
		log.FromContext(ctx).Warn().Int("packages", skipped).
			Msg("osv: packages on ecosystems OSV does not serve were not queried — reported incomplete, not clean")
	}

	idsByPkg, partial, err := c.queryIDs(ctx, queryable)
	if err != nil {
		return nil, nil, fmt.Errorf("Query: %w", err)
	}
	for p := range partial {
		incomplete[p] = true
	}

	unique := map[string]bool{}
	for _, ids := range idsByPkg {
		for _, id := range ids {
			unique[id] = true
		}
	}
	vulns, failed, err := c.hydrate(ctx, unique)
	if err != nil {
		return nil, nil, fmt.Errorf("Query: %w", err)
	}

	out := make(map[Package][]Vuln, len(idsByPkg))
	for pkg, ids := range idsByPkg {
		for _, id := range ids {
			if v, ok := vulns[id]; ok {
				if v.affectsPackage(pkg) {
					out[pkg] = append(out[pkg], v)
				}
			} else if failed[id] {
				incomplete[pkg] = true // an advisory this package needs was not hydrated
			}
		}
	}
	return out, incomplete, nil
}

// batchQuery / batchResult are the /v1/querybatch wire shapes. Results align
// with queries by index.
type batchQuery struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

type batchResult struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}

// queryIDs resolves each package to its advisory IDs via /v1/querybatch,
// chunking to the API's 1000-query cap and draining per-query page tokens.
//
// partial lists packages whose id list is not the whole answer:
//   - packages OSV refused as an invalid ecosystem. Supported filters those out
//     up front, but its list is a snapshot: when OSV drops a family, the 400
//     names the offending query's index, and that one package is removed and
//     the page retried rather than the whole refresh failing;
//   - packages still holding a page token at maxQueryPages: their list stops
//     at the cap, and a truncated list read as complete would resolve the
//     unread advisories' findings as fixed.
func (c *Client) queryIDs(ctx context.Context, pkgs []Package) (out map[Package][]string, partial map[Package]bool, err error) {
	out = make(map[Package][]string)
	partial = map[Package]bool{}
	for start := 0; start < len(pkgs); start += maxBatch {
		chunk := pkgs[start:min(start+maxBatch, len(pkgs))]

		pending := chunk
		tokens := make([]string, len(chunk))
		for page := 0; len(pending) > 0 && page < maxQueryPages; page++ {
			queries := make([]batchQuery, len(pending))
			for i, p := range pending {
				queries[i].Package.Ecosystem = targetFor(p.Ecosystem).queryEcosystem
				queries[i].Package.Name = p.Name
				queries[i].Version = p.Version
				queries[i].PageToken = tokens[i]
			}
			results, err := c.queryBatch(ctx, queries)
			var invalid *errInvalidQuery
			if errors.As(err, &invalid) && invalid.index < len(pending) {
				log.FromContext(ctx).Warn().Str("ecosystem", pending[invalid.index].Ecosystem).
					Msg("osv rejected an ecosystem missing from its served list — package excluded, batch retried")
				partial[pending[invalid.index]] = true
				pending = append(append([]Package(nil), pending[:invalid.index]...), pending[invalid.index+1:]...)
				tokens = append(append([]string(nil), tokens[:invalid.index]...), tokens[invalid.index+1:]...)
				page-- // the retry is the same page, not a new one
				continue
			}
			if err != nil {
				return nil, nil, err
			}
			if len(results) != len(pending) {
				return nil, nil, fmt.Errorf("queryIDs: got %d results for %d queries", len(results), len(pending))
			}

			var nextPending []Package
			var nextTokens []string
			for i, res := range results {
				for _, v := range res.Vulns {
					out[pending[i]] = append(out[pending[i]], v.ID)
				}
				if res.NextPageToken != "" {
					nextPending = append(nextPending, pending[i])
					nextTokens = append(nextTokens, res.NextPageToken)
				}
			}
			pending, tokens = nextPending, nextTokens
		}
		if len(pending) > 0 {
			log.FromContext(ctx).Warn().Int("packages", len(pending)).Int("max_pages", maxQueryPages).
				Msg("osv: advisory pagination hit the page cap — packages reported incomplete")
		}
		for _, p := range pending {
			partial[p] = true
		}
	}
	return out, partial, nil
}

// errInvalidQuery is OSV's 400 for one unacceptable query in a batch:
// {"code":3,"message":"error in query at index 7: ... invalid ecosystem"}.
type errInvalidQuery struct{ index int }

func (e *errInvalidQuery) Error() string {
	return fmt.Sprintf("osv: invalid ecosystem in query %d", e.index)
}

// parseInvalidQuery recognises the invalid-ecosystem 400 body; nil otherwise.
func parseInvalidQuery(body []byte) *errInvalidQuery {
	var msg struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &msg) != nil || !strings.Contains(msg.Message, "invalid ecosystem") {
		return nil
	}
	var idx int
	if _, err := fmt.Sscanf(msg.Message, "error in query at index %d", &idx); err != nil || idx < 0 {
		return nil
	}
	return &errInvalidQuery{index: idx}
}

func (c *Client) queryBatch(ctx context.Context, queries []batchQuery) ([]batchResult, error) {
	payload, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return nil, fmt.Errorf("queryBatch: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/querybatch", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("queryBatch: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("queryBatch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusBadRequest {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if inv := parseInvalidQuery(raw); inv != nil {
			return nil, inv
		}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("queryBatch: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Results []batchResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("queryBatch: decode: %w", err)
	}
	return body.Results, nil
}

// hydrate fetches each advisory once via /v1/vulns/{id} with bounded fan-out.
// It errors only when every fetch failed — partial loss is logged and skipped,
// but the skipped IDs are returned so callers can tell which advisories are
// missing (the reconcile path must NOT treat a transiently-missing advisory as
// "withdrawn" and resolve a still-valid finding).
func (c *Client) hydrate(ctx context.Context, ids map[string]bool) (map[string]Vuln, map[string]bool, error) {
	logger := log.FromContext(ctx)
	var (
		mu     sync.Mutex
		out    = make(map[string]Vuln, len(ids))
		failed = map[string]bool{}
		wg     sync.WaitGroup
		sem    = make(chan struct{}, hydrateConcurrency)
	)
	for id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					mu.Lock()
					failed[id] = true
					mu.Unlock()
					logger.Error().Any("panic", rec).Str("osv_id", id).
						Msg("osv hydrate panicked; advisory skipped")
				}
			}()

			v, err := c.getVuln(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed[id] = true
				logger.Warn().Err(err).Str("osv_id", id).Msg("osv hydrate failed; advisory skipped")
				return
			}
			out[id] = v
		}()
	}
	wg.Wait()

	if len(failed) > 0 && len(out) == 0 {
		return nil, failed, fmt.Errorf("hydrate: all %d advisory fetches failed", len(failed))
	}
	return out, failed, nil
}

func (c *Client) getVuln(ctx context.Context, id string) (Vuln, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/vulns/"+url.PathEscape(id), nil)
	if err != nil {
		return Vuln{}, fmt.Errorf("getVuln: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return Vuln{}, fmt.Errorf("getVuln: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Vuln{}, fmt.Errorf("getVuln: %s: unexpected status %d", id, resp.StatusCode)
	}

	var body struct {
		ID       string        `json:"id"`
		Aliases  []string      `json:"aliases"`
		Upstream []string      `json:"upstream"`
		Summary  string        `json:"summary"`
		Details  string        `json:"details"`
		Affected []affectedPkg `json:"affected"`
		Severity []severity    `json:"severity"`
		// DatabaseSpecific.Severity is GHSA's qualitative label. It is null on
		// every non-GHSA record, which is why it cannot be the only severity input.
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Vuln{}, fmt.Errorf("getVuln: decode: %w", err)
	}
	return Vuln{
		ID:       body.ID,
		Aliases:  body.Aliases,
		Upstream: body.Upstream,
		Summary:  body.Summary,
		Details:  body.Details,
		Severity: resolveSeverity(body.ID, body.DatabaseSpecific.Severity, body.Severity),
		affected: body.Affected,
	}, nil
}

// IsMalicious reports whether an advisory ID comes from the OpenSSF Malicious
// Packages database. Those IDs are MAL-<year>-<n>, and OSV.dev serves them from
// the same query endpoint as ordinary vulnerability advisories, interleaved,
// so they arrive through the ordinary query path and are told apart by ID.
func IsMalicious(advisoryID string) bool {
	return strings.HasPrefix(advisoryID, "MAL-")
}

// severity is one entry of OSV's top-level `severity` array. Type is the scoring
// system ("CVSS_V3", "CVSS_V4", or a vendor label like "Ubuntu"); Score is that
// system's vector or value.
type severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// resolveSeverity picks a finding severity for an advisory.
//
// GHSA's qualitative label wins when present — it is a human-reviewed judgement
// on the advisory as a whole. Everything else is scored from the top-level CVSS
// vector, which is where the DISTRO databases publish severity:
// database_specific is null on DEBIAN-CVE-*/ALPINE-CVE-*/UBUNTU-CVE-* records
// while severity[] carries a CVSS_V3 vector. Reading only the GHSA field
// would default every one of those advisories to medium — no Debian finding
// could ever be high or critical.
//
// A vector we cannot score (CVSS v4, vendor labels) still falls back to medium:
// present but unranked input is not a reason to page or to bury.
//
// MAL-* is decided before either. Those are OpenSSF Malicious Packages
// advisories — "this published version contains malicious code": hijacked
// releases, credential stealers, install-script backdoors. They carry no CVSS
// vector and no GHSA label, because there is nothing to score: the package is
// not vulnerable, it is hostile. Both branches below would therefore miss them
// and drop them to the medium default, putting every one in the monitor band
// at low scores with a blank must_fix_class.
//
// A dependency on a known-malicious release is an assumed compromise of whatever
// installed it, so it is critical by construction rather than by measurement.
func resolveSeverity(advisoryID, ghsaLabel string, scores []severity) finding.Severity {
	if IsMalicious(advisoryID) {
		return finding.SeverityCritical
	}
	if ghsaLabel != "" {
		return mapSeverity(ghsaLabel)
	}
	for _, s := range scores {
		if !strings.EqualFold(s.Type, "CVSS_V3") {
			continue
		}
		if base, ok := cvss3BaseScore(s.Score); ok {
			return severityForBaseScore(base)
		}
	}
	return finding.SeverityMedium
}

// severityForBaseScore maps a CVSS base score to its qualitative band, using the
// CVSS v3.1 §5 rating scale verbatim.
func severityForBaseScore(base float64) finding.Severity {
	switch {
	case base >= 9.0:
		return finding.SeverityCritical
	case base >= 7.0:
		return finding.SeverityHigh
	case base >= 4.0:
		return finding.SeverityMedium
	case base > 0:
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

// mapSeverity normalizes GHSA's severity labels to finding severities. An
// advisory without one (some non-GHSA sources) defaults to medium — present
// but unranked input is not a reason to page or to bury.
func mapSeverity(s string) finding.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return finding.SeverityCritical
	case "HIGH":
		return finding.SeverityHigh
	case "LOW":
		return finding.SeverityLow
	default:
		return finding.SeverityMedium
	}
}
