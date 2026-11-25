package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/collect"
)

func closedCodeAlertJSON(repoFullName string, number int, state, dismissed string, updated time.Time) string {
	return fmt.Sprintf(`{"number":%d,"state":%q,"dismissed_reason":%q,"updated_at":%q,"repository":{"full_name":%q}}`,
		number, state, dismissed, updated.UTC().Format(time.RFC3339), repoFullName)
}

func closedSecretAlertJSON(repoFullName string, number int, resolution string, updated time.Time) string {
	return fmt.Sprintf(`{"number":%d,"state":"resolved","resolution":%q,"updated_at":%q,"repository":{"full_name":%q}}`,
		number, resolution, updated.UTC().Format(time.RFC3339), repoFullName)
}

// A GHAS alert closed on GitHub stops appearing in the open listing; without
// reading the closed listing its finding would stay open until the findings
// TTL. Each closure carries the reason GitHub's state maps to, and only alerts
// on repos the open listing reads are kept (archived repos for secrets only).
func TestCollectGHAS_ClosedAlertsBecomeClosures(t *testing.T) {
	recent := time.Now().Add(-time.Hour)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /orgs/org/code-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") == "open" {
			fmt.Fprint(w, "[]")
			return
		}
		require.Equal(t, "closed", q.Get("state"))
		require.Equal(t, "updated", q.Get("sort"))
		require.Equal(t, "desc", q.Get("direction"))
		fmt.Fprintf(w, "[%s,%s,%s,%s]",
			closedCodeAlertJSON("org/repo1", 7, "fixed", "", recent),
			closedCodeAlertJSON("org/repo0", 8, "dismissed", "false positive", recent),
			closedCodeAlertJSON("org/old", 9, "fixed", "", recent),
			closedCodeAlertJSON("org/not-installed", 10, "fixed", "", recent))
	})
	mux.HandleFunc("GET /orgs/org/secret-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") == "open" {
			fmt.Fprint(w, "[]")
			return
		}
		require.Equal(t, "resolved", q.Get("state"))
		require.Equal(t, "updated", q.Get("sort"))
		fmt.Fprintf(w, "[%s,%s,%s,%s]",
			closedSecretAlertJSON("org/repo0", 3, "revoked", recent),
			closedSecretAlertJSON("org/old", 4, "used_in_tests", recent),
			closedSecretAlertJSON("org/repo1", 5, "pattern_deleted", recent),
			closedSecretAlertJSON("org/not-installed", 6, "revoked", recent))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	fs, closed := c.collectGHAS(context.Background(), srv.URL, "tok-closed", ghasTestRepos())

	require.Empty(t, fs)
	require.ElementsMatch(t, []collect.FindingClosure{
		{ID: "ghas_code_scanning:org/repo1:7", Source: "ghas_code_scanning", Reason: finding.ReasonFixed,
			Note: "fixed on GitHub: code scanning no longer reports it"},
		{ID: "ghas_code_scanning:org/repo0:8", Source: "ghas_code_scanning", Reason: finding.ReasonManual,
			Note: "dismissed on GitHub: false positive"},
		{ID: "ghas_secrets:org/repo0:3", Source: "ghas_secrets", Reason: finding.ReasonFixed,
			Note: "resolved on GitHub: revoked"},
		{ID: "ghas_secrets:org/old:4", Source: "ghas_secrets", Reason: finding.ReasonManual,
			Note: "resolved on GitHub: used in tests"},
		{ID: "ghas_secrets:org/repo1:5", Source: "ghas_secrets", Reason: finding.ReasonProviderClosed,
			Note: "resolved on GitHub: pattern deleted"},
	}, closed)
}

func TestClosureReasons(t *testing.T) {
	code := []struct {
		state, dismissed string
		want             finding.ResolutionReason
		ok               bool
	}{
		{"fixed", "", finding.ReasonFixed, true},
		{"dismissed", "won't fix", finding.ReasonManual, true},
		{"dismissed", "", finding.ReasonManual, true},
		{"open", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range code {
		got, ok := codeScanClosure("o/r", closedCodeScanAlert{Number: 1, State: tc.state, DismissedReason: tc.dismissed})
		require.Equal(t, tc.ok, ok, "code scanning state %q", tc.state)
		require.Equal(t, tc.want, got.Reason, "code scanning state %q", tc.state)
	}

	secret := []struct {
		state, resolution string
		want              finding.ResolutionReason
		ok                bool
	}{
		{"resolved", "revoked", finding.ReasonFixed, true},
		{"resolved", "false_positive", finding.ReasonManual, true},
		{"resolved", "wont_fix", finding.ReasonManual, true},
		{"resolved", "used_in_tests", finding.ReasonManual, true},
		{"resolved", "pattern_edited", finding.ReasonProviderClosed, true},
		{"resolved", "", finding.ReasonProviderClosed, true},
		{"resolved", "some_future_value", finding.ReasonProviderClosed, true},
		{"open", "", "", false},
	}
	for _, tc := range secret {
		got, ok := secretClosure("o/r", closedSecretAlert{Number: 1, State: tc.state, Resolution: tc.resolution})
		require.Equal(t, tc.ok, ok, "secret %q/%q", tc.state, tc.resolution)
		require.Equal(t, tc.want, got.Reason, "secret %q/%q", tc.state, tc.resolution)
	}
}

// The closed listing is sorted newest change first, so paging stops at the
// first alert older than the lookback window instead of reading the org's
// whole closed history every sweep.
func TestListClosedAlerts_StopsAtLookback(t *testing.T) {
	now := time.Now()
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /orgs/org/secret-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		require.LessOrEqual(t, page, 2, "paging must stop at the first alert older than the cutoff")
		fmt.Fprint(w, "[")
		for i := 0; i < perPage; i++ {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			updated := now.Add(-time.Duration((page-1)*perPage+i) * time.Hour)
			fmt.Fprint(w, closedSecretAlertJSON("org/repo0", (page-1)*perPage+i, "revoked", updated))
		}
		fmt.Fprint(w, "]")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	cutoff := now.Add(-150*time.Hour - time.Minute)
	got, err := listClosedAlerts[closedSecretAlert](context.Background(), c,
		srv.URL+"/orgs/org/secret-scanning/alerts?state=resolved&sort=updated&direction=desc", "tok-lookback", cutoff)
	require.NoError(t, err)
	require.Len(t, got, 151, "alerts 0..150 hours old are inside the window")
	require.EqualValues(t, 2, calls.Load())
}

// On the per-repo fallback, a repo's closed listing is read only for a kind
// whose open listing answered for it: a repo without GHAS would 404 that too,
// doubling the wasted calls. An archived repo is never read for code scanning.
func TestCollectGHAS_PerRepoClosedOnlyWhereOpenAnswered(t *testing.T) {
	recent := time.Now().Add(-time.Hour)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/org/repo0/code-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") == "closed" {
			fmt.Fprintf(w, "[%s]", closedCodeAlertJSON("", 7, "fixed", "", recent))
			return
		}
		fmt.Fprint(w, "[]")
	})
	mux.HandleFunc("GET /repos/org/repo0/secret-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") == "resolved" {
			fmt.Fprintf(w, "[%s]", closedSecretAlertJSON("", 3, "false_positive", recent))
			return
		}
		fmt.Fprint(w, "[]")
	})
	mux.HandleFunc("GET /repos/org/repo1/", func(w http.ResponseWriter, r *http.Request) {
		require.NotEqual(t, "closed", r.URL.Query().Get("state"), "repo without GHAS must not be asked for closed alerts")
		require.NotEqual(t, "resolved", r.URL.Query().Get("state"), "repo without GHAS must not be asked for closed alerts")
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("GET /repos/org/old/secret-scanning/alerts", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "[]")
	})
	mux.HandleFunc("GET /repos/org/old/code-scanning/alerts", func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("archived repo must not be swept for code scanning, open or closed")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	_, closed := c.collectGHAS(context.Background(), srv.URL, "tok-closed-fallback", ghasTestRepos())

	require.ElementsMatch(t, []string{"ghas_code_scanning:org/repo0:7", "ghas_secrets:org/repo0:3"}, closureIDs(closed))
}

// At org level the same rule holds per kind: an org whose open code-scanning
// listing failed (and did not fall back) is not asked for its closed
// code-scanning alerts, while its secret-scanning kind, whose open listing
// answered, still reads closures.
func TestCollectGHAS_OrgClosedOnlyWhereOpenAnswered(t *testing.T) {
	recent := time.Now().Add(-time.Hour)
	var closedCodeReads atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /orgs/org/code-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") == "closed" {
			closedCodeReads.Add(1)
			fmt.Fprintf(w, "[%s]", closedCodeAlertJSON("org/repo0", 7, "fixed", "", recent))
			return
		}
		// Neither a 404 nor an unscoped 403, so no per-repo fallback: the
		// listing simply failed this sweep.
		w.WriteHeader(http.StatusUnprocessableEntity)
	})
	mux.HandleFunc("GET /orgs/org/secret-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") == "resolved" {
			fmt.Fprintf(w, "[%s]", closedSecretAlertJSON("org/repo0", 3, "revoked", recent))
			return
		}
		fmt.Fprint(w, "[]")
	})
	mux.HandleFunc("GET /repos/", func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("a failed org listing must not fall back to per-repo calls: %s", r.URL.Path)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestCollector(srv)
	_, closed := c.collectGHAS(context.Background(), srv.URL, "tok-closed-org-failed", ghasTestRepos())

	require.Zero(t, closedCodeReads.Load(), "closed code-scanning alerts read although the open listing failed")
	require.Equal(t, []string{"ghas_secrets:org/repo0:3"}, closureIDs(closed))
}

// GitHub's own validity check is carried onto the finding; a value GitHub does
// not define is recorded as absent (unknown), never guessed.
func TestSecretFinding_CarriesValidity(t *testing.T) {
	r := repo{Name: "repo0", FullName: "org/repo0"}
	for _, tc := range []struct{ in, want string }{
		{"active", finding.SecretValidityActive},
		{"INACTIVE", finding.SecretValidityInactive},
		{"unknown", finding.SecretValidityUnknown},
		{"", ""},
		{"maybe", ""},
	} {
		f := secretFinding(r, secretAlert{Number: 1, SecretType: "aws_access_key_id", Validity: tc.in}, time.Now())
		got, present := f.Metadata[finding.SecretValidityKey]
		require.Equal(t, tc.want, got, "validity %q", tc.in)
		require.Equal(t, tc.want != "", present, "validity %q", tc.in)
	}
}

func closureIDs(cs []collect.FindingClosure) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}
