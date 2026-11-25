// Package epss is the FIRST.org Exploit Prediction Scoring System feed (part of
// the supply-chain intel feeds). EPSS gives each CVE a 0–1 probability of exploitation in
// the next 30 days — the "how likely" signal KEV (binary exploited/not) and CVSS
// (severity) don't carry. Scores are held in an in-memory catalog refreshed
// daily and read by the enrich EPSS source; nothing is persisted on the finding.
package epss

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// csvURL is FIRST.org's published daily EPSS score export (gzipped CSV).
const csvURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

const httpTimeout = 60 * time.Second

// Catalog is an immutable CVE → EPSS-probability map. scoreDate is the feed's
// own "score_date" (when FIRST.org computed the scores) — the feed-side
// freshness signal, distinct from when we last fetched. Zero if the feed
// carried no parseable score_date.
type Catalog struct {
	scores    map[string]float64
	scoreDate time.Time
}

// NewCatalog builds a catalog from a CVE → score map (used by tests and Fetch).
// CVE IDs are upper-cased so lookups are case-insensitive.
func NewCatalog(scores map[string]float64) *Catalog {
	m := make(map[string]float64, len(scores))
	for cve, s := range scores {
		m[strings.ToUpper(cve)] = s
	}
	return &Catalog{scores: m}
}

// Score returns the EPSS probability for cve and whether it was present.
func (c *Catalog) Score(cve string) (float64, bool) {
	s, ok := c.scores[strings.ToUpper(cve)]
	return s, ok
}

// Len is the number of scored CVEs.
func (c *Catalog) Len() int { return len(c.scores) }

// ScoreDate is the feed's own computation date (zero if the feed omitted it).
func (c *Catalog) ScoreDate() time.Time { return c.scoreDate }

// Cache is the thread-safe holder shared between the periodic refresh job (which
// Sets a freshly-fetched catalog) and the enrich source (which reads scores). It
// starts empty, so EPSS simply contributes nothing until the first refresh.
type Cache struct {
	mu  sync.RWMutex
	cat *Catalog
}

func NewCache() *Cache { return &Cache{cat: NewCatalog(nil)} }

func (c *Cache) Set(cat *Catalog) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cat = cat
}

// Score reads the current catalog (empty-safe).
func (c *Cache) Score(cve string) (float64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cat.Score(cve)
}

// ScoreDate is the current catalog's feed-side computation date (zero if never
// set or the feed omitted it).
// Loaded reports whether a non-empty catalog has been set — false from boot
// until the first successful refresh, and for as long as the feed keeps failing.
func (c *Cache) Loaded() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cat.Len() > 0
}

func (c *Cache) ScoreDate() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cat.ScoreDate()
}

// Fetcher downloads the EPSS catalog over HTTP.
type Fetcher struct {
	client *http.Client
	url    string
}

func NewFetcher() *Fetcher {
	return &Fetcher{client: safenet.New(httpTimeout), url: csvURL}
}

// Fetch downloads and parses the current EPSS export. The file is a gzipped CSV
// whose first line is a "#model_version,score_date" comment, followed by a
// cve,epss,percentile header and one row per CVE.
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

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Fetch: gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	return parseCSV(gz)
}

// parseCSV reads the EPSS CSV (comment + header skipped) into a catalog. The
// leading "#model_version:...,score_date:..." comment is peeked for the feed's
// score_date before the csv reader (which also skips '#' lines) parses the rows.
func parseCSV(r io.Reader) (*Catalog, error) {
	br := bufio.NewReader(r)
	var scoreDate time.Time
	if first, err := br.ReadString('\n'); err == nil || errors.Is(err, io.EOF) {
		if strings.HasPrefix(first, "#") {
			scoreDate = parseScoreDate(first)
		} else {
			// Not a comment (defensive): put the line back so csv sees it.
			r = io.MultiReader(strings.NewReader(first), br)
			br = bufio.NewReader(r)
		}
	}

	cr := csv.NewReader(br)
	cr.Comment = '#'        // drops any remaining "#..." metadata line
	cr.FieldsPerRecord = -1 // tolerate trailing columns / blank lines
	scores := map[string]float64{}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parseCSV: %w", err)
		}
		if len(rec) < 2 || rec[0] == "cve" {
			continue // header row or short line
		}
		s, err := strconv.ParseFloat(rec[1], 64)
		if err != nil {
			continue // skip malformed score rows rather than fail the whole feed
		}
		scores[strings.ToUpper(rec[0])] = s
	}
	cat := NewCatalog(scores)
	cat.scoreDate = scoreDate
	return cat, nil
}

// parseScoreDate extracts the score_date from the EPSS header comment, e.g.
// "#model_version:v2023.03.01,score_date:2026-07-19T00:00:00+0000". Returns the
// zero time if no parseable date is present.
func parseScoreDate(comment string) time.Time {
	for part := range strings.SplitSeq(strings.TrimPrefix(strings.TrimSpace(comment), "#"), ",") {
		k, v, ok := strings.Cut(part, ":")
		if !ok || strings.TrimSpace(k) != "score_date" {
			continue
		}
		v = strings.TrimSpace(v)
		for _, layout := range []string{"2006-01-02T15:04:05-0700", time.RFC3339, "2006-01-02"} {
			if t, err := time.Parse(layout, v); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}
