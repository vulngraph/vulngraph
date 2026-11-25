// Package kev is the CISA Known Exploited Vulnerabilities intel feed (part of
// the supply-chain intel feeds). It fetches the public KEV catalog and answers whether
// a CVE is known to be exploited in the wild — the strongest signal that a
// vulnerability finding must be escalated, not merely queued.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// catalogURL is CISA's published KEV feed.
const catalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

const httpTimeout = 30 * time.Second

// Entry is one catalog row. DateAdded is CISA's dateAdded (the day the CVE
// joined the catalog); zero when the feed's value did not parse — unknown,
// never a guessed date.
type Entry struct {
	CVEID     string
	DateAdded time.Time
	Name      string
}

// Catalog is an immutable set of known-exploited CVEs. released is the feed's
// own "dateReleased" — the feed-side freshness signal, distinct from when we
// last fetched. Zero if the feed carried no parseable date.
type Catalog struct {
	cves     map[string]Entry
	released time.Time
}

// NewCatalog builds a catalog from bare CVE ids (no dateAdded). IDs are
// upper-cased so lookups are case-insensitive.
func NewCatalog(cveIDs []string) *Catalog {
	entries := make([]Entry, len(cveIDs))
	for i, id := range cveIDs {
		entries[i] = Entry{CVEID: id}
	}
	return NewCatalogFromEntries(entries)
}

// NewCatalogFromEntries builds a catalog from full entries (used by Fetch).
func NewCatalogFromEntries(entries []Entry) *Catalog {
	set := make(map[string]Entry, len(entries))
	for _, e := range entries {
		e.CVEID = strings.ToUpper(e.CVEID)
		set[e.CVEID] = e
	}
	return &Catalog{cves: set}
}

// IsKnownExploited reports whether cve is in the catalog.
func (c *Catalog) IsKnownExploited(cve string) bool {
	_, ok := c.cves[strings.ToUpper(cve)]
	return ok
}

// Entries returns every entry, CVE ids upper-cased. Order is unspecified.
func (c *Catalog) Entries() []Entry {
	out := make([]Entry, 0, len(c.cves))
	for _, e := range c.cves {
		out = append(out, e)
	}
	return out
}

// Len is the number of CVEs in the catalog.
func (c *Catalog) Len() int { return len(c.cves) }

// CVEIDs returns every CVE id in the catalog (already upper-cased by
// NewCatalog), for pushing into finding.Filter.CVEIn — the escalation scan's
// own pre-aggregation filter, so it scans the handful of findings that could
// possibly match instead of every open finding for a source. Order is
// unspecified (map iteration).
func (c *Catalog) CVEIDs() []string {
	ids := make([]string, 0, len(c.cves))
	for id := range c.cves {
		ids = append(ids, id)
	}
	return ids
}

// Released is the feed's own publish date (zero if the feed omitted it).
func (c *Catalog) Released() time.Time { return c.released }

// Fetcher retrieves the KEV catalog over HTTP.
type Fetcher struct {
	client *http.Client
	url    string
}

func NewFetcher() *Fetcher {
	return &Fetcher{client: safenet.New(httpTimeout), url: catalogURL}
}

// Fetch downloads and parses the current KEV catalog.
func (f *Fetcher) Fetch(ctx context.Context) (*Catalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("Fetch: %w", err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Fetch: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		DateReleased    string `json:"dateReleased"`
		Vulnerabilities []struct {
			CVEID             string `json:"cveID"`
			DateAdded         string `json:"dateAdded"`
			VulnerabilityName string `json:"vulnerabilityName"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("Fetch: decode: %w", err)
	}
	entries := make([]Entry, 0, len(body.Vulnerabilities))
	for _, v := range body.Vulnerabilities {
		if v.CVEID == "" {
			continue
		}
		// dateAdded is a calendar date, e.g. "2021-12-10".
		added, _ := time.Parse("2006-01-02", v.DateAdded)
		entries = append(entries, Entry{CVEID: v.CVEID, DateAdded: added, Name: v.VulnerabilityName})
	}
	cat := NewCatalogFromEntries(entries)
	// dateReleased is an RFC3339 timestamp, e.g. "2026-07-19T14:00:00.000Z".
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, body.DateReleased); err == nil {
			cat.released = t
			break
		}
	}
	return cat, nil
}

// Enrich flags KnownExploited on findings whose CVE is KEV-listed and returns
// only the findings that changed, so the caller writes (and re-enriches) only
// those. Severity is left alone: it is the producer's raw input and lives on
// the findings row, which only lifecycle writers touch; the enrichment KEV
// source turns the flag into a page floor. Safe for concurrent readers of the
// catalog.
func Enrich(cat *Catalog, findings []finding.Finding) []finding.Finding {
	var changed []finding.Finding
	for _, f := range findings {
		if f.KnownExploited || !cat.IsKnownExploited(findingCVE(f)) {
			continue
		}
		f.KnownExploited = true
		changed = append(changed, f)
	}
	return changed
}

// OpenFindingsByCVE counts findings per catalog CVE (upper-cased), for the
// kev.added record. Findings whose CVE is not in the catalog are skipped.
func OpenFindingsByCVE(cat *Catalog, findings []finding.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		if cve := strings.ToUpper(findingCVE(f)); cat.IsKnownExploited(cve) {
			out[cve]++
		}
	}
	return out
}

// findingCVE resolves the CVE a finding maps to: its CheckID when that is itself
// a CVE id (scanner/OSV findings), else its "cve" metadata (nuclei templates
// that key on a template slug but carry the CVE in classification metadata).
func findingCVE(f finding.Finding) string {
	if strings.HasPrefix(strings.ToUpper(f.CheckID), "CVE-") {
		return f.CheckID
	}
	return f.Metadata["cve"]
}
