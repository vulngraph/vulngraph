package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestCatalog_IsKnownExploited_CaseInsensitive(t *testing.T) {
	c := NewCatalog([]string{"CVE-2021-44228", "cve-2017-0144"})
	require.True(t, c.IsKnownExploited("CVE-2021-44228"))
	require.True(t, c.IsKnownExploited("cve-2021-44228"), "lookup is case-insensitive")
	require.True(t, c.IsKnownExploited("CVE-2017-0144"))
	require.False(t, c.IsKnownExploited("CVE-2099-0000"))
	require.Equal(t, 2, c.Len())
}

func TestFetch_ParsesCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"dateReleased":"2026-07-19T14:00:00.000Z","vulnerabilities":[{"cveID":"CVE-2021-44228"},{"cveID":"CVE-2014-0160"},{"cveID":""}]}`))
	}))
	t.Cleanup(srv.Close)

	f := &Fetcher{client: srv.Client(), url: srv.URL}
	cat, err := f.Fetch(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, cat.Len(), "blank CVE IDs are skipped")
	require.True(t, cat.IsKnownExploited("CVE-2021-44228"))
	require.False(t, cat.Released().IsZero(), "dateReleased is parsed")
	require.Equal(t, 2026, cat.Released().Year())
}

func TestFetch_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	f := &Fetcher{client: srv.Client(), url: srv.URL}
	_, err := f.Fetch(context.Background())
	require.ErrorContains(t, err, "status 503")
}

func TestEnrich_FlagsKEVFindings(t *testing.T) {
	cat := NewCatalog([]string{"CVE-2021-44228"})
	findings := []finding.Finding{
		{ID: "1", CheckID: "CVE-2021-44228", Severity: finding.SeverityMedium},                       // KEV → flag
		{ID: "2", CheckID: "CVE-2099-0000", Severity: finding.SeverityHigh},                          // not KEV → unchanged
		{ID: "3", CheckID: "CVE-2021-44228", Severity: finding.SeverityCritical},                     // critical but unflagged → flag it
		{ID: "4", CheckID: "CVE-2021-44228", Severity: finding.SeverityMedium, KnownExploited: true}, // already flagged → skip
	}

	changed := Enrich(cat, findings)

	byID := map[string]finding.Finding{}
	for _, f := range changed {
		byID[f.ID] = f
	}
	require.Len(t, changed, 2)
	require.True(t, byID["1"].KnownExploited)
	require.True(t, byID["3"].KnownExploited)
	require.Equal(t, finding.SeverityMedium, byID["1"].Severity,
		"severity is the producer's raw input — the KEV page floor lives in the score, not here")
}

func TestEnrich_NoKEVMatches(t *testing.T) {
	cat := NewCatalog([]string{"CVE-2021-44228"})
	changed := Enrich(cat, []finding.Finding{{CheckID: "aws-ec2-public-ip", Severity: finding.SeverityMedium}})
	require.Empty(t, changed)
}

func TestEnrich_MatchesCVEInMetadata(t *testing.T) {
	// A nuclei template keyed on a slug carries the CVE in metadata; it must
	// still escalate when that CVE is KEV-listed.
	cat := NewCatalog([]string{"CVE-2021-44228"})
	findings := []finding.Finding{
		{ID: "tpl", CheckID: "log4j-rce", Severity: finding.SeverityHigh, Metadata: map[string]string{"cve": "CVE-2021-44228"}},
		{ID: "tpl-lower", CheckID: "log4j-rce", Severity: finding.SeverityHigh, Metadata: map[string]string{"cve": "cve-2021-44228"}},
		{ID: "tpl-none", CheckID: "tech-detect", Severity: finding.SeverityInfo, Metadata: map[string]string{"cve": "CVE-2099-0000"}},
		{ID: "no-meta", CheckID: "tech-detect", Severity: finding.SeverityInfo},
	}

	changed := Enrich(cat, findings)

	byID := map[string]finding.Finding{}
	for _, f := range changed {
		byID[f.ID] = f
	}
	require.Len(t, changed, 2)
	require.Contains(t, byID, "tpl")
	require.Contains(t, byID, "tpl-lower")
	require.True(t, byID["tpl"].KnownExploited)
}

func TestFetch_ParsesDateAddedAndName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[
			{"cveID":"cve-2021-44228","dateAdded":"2021-12-10","vulnerabilityName":"Apache Log4j2 RCE"},
			{"cveID":"CVE-2014-0160","dateAdded":"not a date"}]}`))
	}))
	t.Cleanup(srv.Close)

	cat, err := (&Fetcher{client: srv.Client(), url: srv.URL}).Fetch(context.Background())
	require.NoError(t, err)
	byID := map[string]Entry{}
	for _, e := range cat.Entries() {
		byID[e.CVEID] = e
	}
	require.Equal(t, Entry{CVEID: "CVE-2021-44228", DateAdded: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC), Name: "Apache Log4j2 RCE"}, byID["CVE-2021-44228"])
	require.True(t, byID["CVE-2014-0160"].DateAdded.IsZero(), "an unparseable dateAdded is unknown, not guessed")
}

func TestOpenFindingsByCVE(t *testing.T) {
	cat := NewCatalog([]string{"CVE-2021-44228", "CVE-2014-0160"})
	got := OpenFindingsByCVE(cat, []finding.Finding{
		{CheckID: "CVE-2021-44228"},
		{CheckID: "cve-2021-44228"},
		{CheckID: "log4j-rce", Metadata: map[string]string{"cve": "CVE-2021-44228"}},
		{CheckID: "CVE-2099-0000"},
	})
	require.Equal(t, map[string]int{"CVE-2021-44228": 3}, got)
}
