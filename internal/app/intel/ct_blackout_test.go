package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCheckCTLogs_TotalBlackoutIsAnError is the guard against a detection going
// dark without a single complaint.
//
// crt.sh is the only upstream the phishing pipeline has, it has no fallback, and
// it can serve 502 for extended periods (on every monitored base name and on
// its own root URL). CheckCTLogs used to swallow every
// per-domain error with a bare `continue` under the comment "Best-effort per
// domain — log at caller level", and no caller logged anything. So a total
// upstream blackout returned ([], nil), RunScan logged hits=0, the job COMPLETED
// SUCCESSFULLY, and phishing_candidates simply stopped growing — no new rows
// and no error anywhere.
//
// The distinction this pins is the one the old code could not express: "no
// squatting domains exist" versus "we could not look". Only the first is a clean
// bill of health.
func TestCheckCTLogs_TotalBlackoutIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
	}))
	defer srv.Close()

	c := &ctClient{http: srv.Client(), urlFmt: srv.URL + "/?q=%s&output=json"}
	hits, stats, err := c.CheckCTLogs(context.Background(), []string{"zeta.test", "zeta-corp.test"})

	require.Error(t, err,
		"every crt.sh query failed and CheckCTLogs reported success — that is a "+
			"silent outage: a total upstream blackout must not be indistinguishable from "+
			"'no phishing domains found'")
	require.Empty(t, hits, "no hits can be produced when every query failed")
	require.Equal(t, 2, stats.Queried)
	require.Equal(t, 2, stats.Failed, "both failures must be counted, not discarded")
}

// TestCheckCTLogs_PartialFailureStillScans pins the other half: one upstream
// hiccup must not abandon the domains that DID answer. Candidates are only ever
// inserted by this path — never resolved or deleted by absence — so proceeding on
// partial data cannot destroy anything, which is what makes tolerating it safe.
func TestCheckCTLogs_PartialFailureStillScans(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "zeta-corp") {
			http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// A near-miss of zeta.test, above ctSimilarityThreshold and not an exact
		// match, so it must survive scoring and land as a hit.
		_, _ = w.Write([]byte(`[{"issuer_name":"C=US, O=Let's Encrypt, CN=R3",
			"common_name":"zetx.test","name_value":"zetx.test",
			"not_before":"2026-08-01T00:00:00","not_after":"2026-11-01T00:00:00"}]`))
	}))
	defer srv.Close()

	c := &ctClient{http: srv.Client(), urlFmt: srv.URL + "/?q=%s&output=json"}
	hits, stats, err := c.CheckCTLogs(context.Background(), []string{"zeta.test", "zeta-corp.test"})

	require.NoError(t, err, "a partial failure must not abandon the domains that answered")
	require.Equal(t, 2, stats.Queried)
	require.Equal(t, 1, stats.Failed, "the failed domain must still be counted so the gap is visible")
	require.NotEmpty(t, hits, "the domain that answered must still produce its hits")
}

// TestCheckCTLogs_UnscannableDomainIsNotCountedAsQueried pins the denominator of
// the total-blackout check. A domain that yields no base name is never attempted,
// so counting it as queried would let unscannable rows mask a real outage: with
// two rows, one unattempted, Failed would read 1 of 2 rather than 1 of 1 and the
// blackout check would stay silent.
//
// Not to be confused with a malformed row such as "zeta,cin" (a typo) in
// intel_monitored_domains: splitDomain finds
// no dot in it, so it returns the WHOLE string as the base and the row IS
// queried — as `q=%zeta,cin%`, which can never match anything. That is a
// permanently wasted query and a permanent contribution to Failed, not an
// unscannable row. NormalizeDomain rejects that string today, so it cannot be
// added through the API any more; a row that predates the validation needs
// deleting by hand.
func TestCheckCTLogs_UnscannableDomainIsNotCountedAsQueried(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
	}))
	defer srv.Close()

	c := &ctClient{http: srv.Client(), urlFmt: srv.URL + "/?q=%s&output=json"}
	_, stats, err := c.CheckCTLogs(context.Background(), []string{"zeta.test", ""})

	require.Equal(t, 1, stats.Queried, "a domain with no usable base name was never attempted")
	require.Equal(t, 1, stats.Failed)
	require.Error(t, err, "1 failure out of 1 attempt is a total blackout and must be reported")
}
