package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// fakeOSV serves /v1/querybatch from vulnsByPkg (keyed "ecosystem/name@version")
// and /v1/vulns/{id} from records.
type fakeOSV struct {
	vulnsByPkg map[string][]string
	records    map[string]string // id → raw JSON
	batchCalls atomic.Int32
}

func (f *fakeOSV) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		f.batchCalls.Add(1)
		var body struct {
			Queries []batchQuery `json:"queries"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.LessOrEqual(t, len(body.Queries), maxBatch)

		fmt.Fprint(w, `{"results":[`)
		for i, q := range body.Queries {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			key := q.Package.Ecosystem + "/" + q.Package.Name + "@" + q.Version
			ids := f.vulnsByPkg[key]
			fmt.Fprint(w, `{"vulns":[`)
			for j, id := range ids {
				if j > 0 {
					fmt.Fprint(w, ",")
				}
				fmt.Fprintf(w, `{"id":%q,"modified":"2026-01-01T00:00:00Z"}`, id)
			}
			fmt.Fprint(w, `]}`)
		}
		fmt.Fprint(w, `]}`)
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		rec, ok := f.records[r.PathValue("id")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, rec)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newTestClient points a client at the fake server (bypassing safenet, which
// blocks loopback addresses).
func newTestClient(srv *httptest.Server) *Client {
	return &Client{client: srv.Client(), baseURL: srv.URL}
}

const lodashGHSA = `{
	"id": "GHSA-35jh-r3h4-6jhm",
	"aliases": ["CVE-2021-23337"],
	"summary": "Command injection in lodash",
	"database_specific": {"severity": "HIGH"},
	"affected": [{
		"package": {"ecosystem": "npm", "name": "lodash"},
		"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
	}]
}`

func TestQuery_ResolvesAndHydrates(t *testing.T) {
	fake := &fakeOSV{
		vulnsByPkg: map[string][]string{"npm/lodash@4.17.20": {"GHSA-35jh-r3h4-6jhm"}},
		records:    map[string]string{"GHSA-35jh-r3h4-6jhm": lodashGHSA},
	}
	c := newTestClient(fake.server(t))

	lodash := Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	clean := Package{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}
	got, _, err := c.Query(context.Background(), []Package{lodash, clean})
	require.NoError(t, err)

	require.Len(t, got[lodash], 1)
	require.Empty(t, got[clean])
	v := got[lodash][0]
	require.Equal(t, "GHSA-35jh-r3h4-6jhm", v.ID)
	require.Equal(t, "CVE-2021-23337", v.CVE())
	require.Equal(t, finding.SeverityHigh, v.Severity)
	require.Equal(t, "4.17.21", v.FixedVersion(lodash))
	require.Empty(t, v.FixedVersion(clean), "fix is per affected package")
}

func TestQuery_HydratesSharedVulnOnce(t *testing.T) {
	var vulnFetches atomic.Int32
	fake := &fakeOSV{
		vulnsByPkg: map[string][]string{
			"npm/a@1.0.0": {"GHSA-x"},
			"npm/b@2.0.0": {"GHSA-x"},
		},
		records: map[string]string{"GHSA-x": `{"id":"GHSA-x","database_specific":{"severity":"LOW"}}`},
	}
	srv := fake.server(t)
	// Wrap to count vuln fetches.
	inner := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			vulnFetches.Add(1)
		}
		inner.ServeHTTP(w, r)
	})

	got, _, err := newTestClient(srv).Query(context.Background(), []Package{
		{Ecosystem: "npm", Name: "a", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "b", Version: "2.0.0"},
	})
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, int32(1), vulnFetches.Load(), "shared advisory hydrated once")
}

func TestQuery_ChunksToBatchCap(t *testing.T) {
	fake := &fakeOSV{}
	c := newTestClient(fake.server(t))

	pkgs := make([]Package, maxBatch+1)
	for i := range pkgs {
		pkgs[i] = Package{Ecosystem: "npm", Name: fmt.Sprintf("p%d", i), Version: "1.0.0"}
	}
	_, _, err := c.Query(context.Background(), pkgs)
	require.NoError(t, err)
	require.Equal(t, int32(2), fake.batchCalls.Load(), "1001 packages need two batch calls")
}

func TestQuery_DrainsPageTokens(t *testing.T) {
	// First call returns one id and a token; the follow-up (with the token)
	// returns the second id and no token.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Queries []batchQuery `json:"queries"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Len(t, body.Queries, 1)
		if body.Queries[0].PageToken == "" {
			fmt.Fprint(w, `{"results":[{"vulns":[{"id":"GHSA-1"}],"next_page_token":"t1"}]}`)
			return
		}
		require.Equal(t, "t1", body.Queries[0].PageToken)
		fmt.Fprint(w, `{"results":[{"vulns":[{"id":"GHSA-2"}]}]}`)
	})
	for _, id := range []string{"GHSA-1", "GHSA-2"} {
		mux.HandleFunc("GET /v1/vulns/"+id, func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, `{"id":%q}`, id)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	p := Package{Ecosystem: "npm", Name: "big", Version: "1.0.0"}
	got, _, err := newTestClient(srv).Query(context.Background(), []Package{p})
	require.NoError(t, err)
	require.Len(t, got[p], 2)
}

func TestQuery_PartialHydrateFailureDegrades(t *testing.T) {
	fake := &fakeOSV{
		vulnsByPkg: map[string][]string{"npm/a@1.0.0": {"GHSA-ok", "GHSA-missing"}},
		records:    map[string]string{"GHSA-ok": `{"id":"GHSA-ok"}`}, // GHSA-missing 404s
	}
	p := Package{Ecosystem: "npm", Name: "a", Version: "1.0.0"}
	got, _, err := newTestClient(fake.server(t)).Query(context.Background(), []Package{p})
	require.NoError(t, err)
	require.Len(t, got[p], 1, "missing advisory skipped, refresh not lost")
	require.Equal(t, "GHSA-ok", got[p][0].ID)
}

func TestQuery_AllHydrateFailuresError(t *testing.T) {
	fake := &fakeOSV{vulnsByPkg: map[string][]string{"npm/a@1.0.0": {"GHSA-missing"}}}
	_, _, err := newTestClient(fake.server(t)).Query(context.Background(), []Package{
		{Ecosystem: "npm", Name: "a", Version: "1.0.0"},
	})
	require.ErrorContains(t, err, "advisory fetches failed")
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		in   string
		want finding.Severity
	}{
		{"CRITICAL", finding.SeverityCritical},
		{"HIGH", finding.SeverityHigh},
		{"Moderate", finding.SeverityMedium},
		{"LOW", finding.SeverityLow},
		{"", finding.SeverityMedium},
		{"UNKNOWN", finding.SeverityMedium},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, mapSeverity(tt.in), "severity %q", tt.in)
	}
}

// debianCVE is the DEBIAN-CVE-2024-2511 record as the live API serves it
// (trimmed to the fields this client decodes): no aliases,
// the CVE in `upstream`, null database_specific, and the CVSS vector at the top
// level. Every distro advisory in OSV has this shape.
const debianCVE = `{
	"id": "DEBIAN-CVE-2024-2511",
	"upstream": ["CVE-2024-2511"],
	"summary": "Unbounded memory growth with session handling in TLSv1.3",
	"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
	"affected": [{
		"package": {"ecosystem": "Debian:12", "name": "openssl"},
		"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.13-1~deb12u1"}]}]
	}]
}`

// A distro advisory must yield a CVE-shaped identifier and a CVSS-derived
// severity. Otherwise every Debian finding gets a non-CVE-shaped check_id,
// none known_exploited, none high or critical — kev.findingCVE and EPSS.Evaluate both
// require the "CVE-" prefix, and a GHSA-only severity field is empty for them.
func TestQuery_DistroAdvisory_UsesUpstreamCVEAndCVSS(t *testing.T) {
	fake := &fakeOSV{
		vulnsByPkg: map[string][]string{"Debian:12/openssl@3.0.11-1~deb12u2": {"DEBIAN-CVE-2024-2511"}},
		records:    map[string]string{"DEBIAN-CVE-2024-2511": debianCVE},
	}
	pkg := Package{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1~deb12u2"}
	got, _, err := newTestClient(fake.server(t)).Query(context.Background(), []Package{pkg})
	require.NoError(t, err)
	require.Len(t, got[pkg], 1)

	v := got[pkg][0]
	require.Equal(t, "CVE-2024-2511", v.CVE(),
		"the CVE lives in upstream on distro records; aliases is empty")
	require.Equal(t, finding.SeverityMedium, v.Severity,
		"CVSS:3.1 base 5.9 is genuinely medium — derived, not defaulted (see the alpine case)")
	require.Equal(t, "3.0.13-1~deb12u1", v.FixedVersion(pkg),
		"the release-qualified ecosystem must match the affected entry")
}

// alpineCVE is the ALPINE-CVE-2023-5363 record as the live API serves it
// (trimmed). Its CVSS base score is 7.5 — a HIGH that the
// GHSA-only severity read reported as medium, on every Alpine package.
const alpineCVE = `{
	"id": "ALPINE-CVE-2023-5363",
	"upstream": ["CVE-2023-5363"],
	"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
	"affected": [{
		"package": {"ecosystem": "Alpine:v3.19", "name": "openssl"},
		"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.4-r1"}]}]
	}]
}`

func TestQuery_DistroAdvisory_EscalatesOnCVSS(t *testing.T) {
	fake := &fakeOSV{
		vulnsByPkg: map[string][]string{"Alpine:v3.19/openssl@3.1.4-r5": {"ALPINE-CVE-2023-5363"}},
		records:    map[string]string{"ALPINE-CVE-2023-5363": alpineCVE},
	}
	pkg := Package{Ecosystem: "Alpine:v3.19", Name: "openssl", Version: "3.1.4-r5"}
	got, _, err := newTestClient(fake.server(t)).Query(context.Background(), []Package{pkg})
	require.NoError(t, err)
	require.Len(t, got[pkg], 1)
	require.Equal(t, "CVE-2023-5363", got[pkg][0].CVE())
	require.Equal(t, finding.SeverityHigh, got[pkg][0].Severity,
		"CVSS:3.1 base 7.5 is high; database_specific is null on every distro record")
}

func TestCVE_PrefersAliasOverUpstream(t *testing.T) {
	v := Vuln{Aliases: []string{"GHSA-x", "CVE-2021-1"}, Upstream: []string{"CVE-2020-9"}}
	require.Equal(t, "CVE-2021-1", v.CVE())
	require.Equal(t, "CVE-2020-9", Vuln{Upstream: []string{"CVE-2020-9"}}.CVE())
	require.Empty(t, Vuln{Aliases: []string{"GHSA-x"}}.CVE())
}

// The CVSS v3.1 base-score formula, pinned against vectors whose published base
// scores are fixed public facts.
func TestCVSS3BaseScore(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9}, // CVE-2024-2511
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5}, // CVE-2023-5363-style
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8}, // classic critical
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8}, // low
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1}, // scope changed
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5}, // v3.0 scores identically
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0},   // no impact
	}
	for _, tc := range tests {
		got, ok := cvss3BaseScore(tc.vector)
		require.True(t, ok, "vector %q must parse", tc.vector)
		require.InDelta(t, tc.want, got, 0.001, "vector %q", tc.vector)
	}

	for _, bad := range []string{
		"", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
		"CVSS:3.1/AV:N/AC:L/PR:N", // truncated: a defaulted metric invents a severity
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	} {
		_, ok := cvss3BaseScore(bad)
		require.False(t, ok, "vector %q must not be scored", bad)
	}
}

func TestResolveSeverity(t *testing.T) {
	cvssHigh := []severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}

	// GHSA's reviewed label wins over the vector when both are present.
	require.Equal(t, finding.SeverityCritical, resolveSeverity("CVE-2026-1", "CRITICAL", cvssHigh))
	// Distro records: no label, vector decides.
	require.Equal(t, finding.SeverityHigh, resolveSeverity("CVE-2026-1", "", cvssHigh))
	// Vendor-only scores stay at the medium default rather than being invented.
	require.Equal(t, finding.SeverityMedium, resolveSeverity("CVE-2026-1", "", []severity{{Type: "Ubuntu", Score: "low"}}))
	// CVSS v4 is not scored here; medium default, never a guess.
	require.Equal(t, finding.SeverityMedium, resolveSeverity("CVE-2026-1", "", []severity{
		{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"},
	}))
	// The DECLARED type governs, not the vector's shape. Every non-v3 type OSV
	// actually publishes carries a vector cvss3BaseScore rejects on its own
	// (v2 has no "CVSS:3" prefix, v4 has "CVSS:4.0", vendor labels are words), so
	// nothing in the live feed can distinguish the type filter from its absence.
	// This pins the contract anyway: a feed that mislabels a v3 vector under
	// another type must not be scored off it — reading a vector the publisher did
	// not claim is v3 is exactly how a severity gets invented.
	require.Equal(t, finding.SeverityMedium, resolveSeverity("CVE-2026-1", "", []severity{
		{Type: "CVSS_V4", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}))
	require.Equal(t, finding.SeverityMedium, resolveSeverity("CVE-2026-1", "", nil))
}

func TestSeverityForBaseScore(t *testing.T) {
	require.Equal(t, finding.SeverityCritical, severityForBaseScore(9.0))
	require.Equal(t, finding.SeverityHigh, severityForBaseScore(8.9))
	require.Equal(t, finding.SeverityHigh, severityForBaseScore(7.0))
	require.Equal(t, finding.SeverityMedium, severityForBaseScore(6.9))
	require.Equal(t, finding.SeverityMedium, severityForBaseScore(4.0))
	require.Equal(t, finding.SeverityLow, severityForBaseScore(3.9))
	require.Equal(t, finding.SeverityInfo, severityForBaseScore(0))
}

// A MAL-* advisory is an OpenSSF Malicious Packages record — "this published
// version contains malicious code" — and carries neither a CVSS vector nor a
// GHSA label, because there is nothing to score: the package is not vulnerable,
// it is hostile. Both of resolveSeverity's branches therefore missed them and
// they fell to the medium default, which put every one in the monitor band at
// low scores with a blank must_fix_class.
//
// OSV.dev serves these from the same query endpoint as ordinary advisories, so
// they were already arriving and were simply not recognised.
func TestResolveSeverity_MaliciousPackageAdvisoryIsCritical(t *testing.T) {
	require.Equal(t, finding.SeverityCritical, resolveSeverity("MAL-2025-21003", "", nil),
		"a known-malicious release is an assumed compromise of whatever installed it")

	// It wins over a weaker explicit label too — the advisory database's own
	// qualitative field is about exploitability, not about hostility.
	require.Equal(t, finding.SeverityCritical, resolveSeverity("MAL-2025-21003", "LOW", nil))

	// And it must not swallow ordinary advisories that merely start with M.
	require.Equal(t, finding.SeverityMedium, resolveSeverity("MALFORMED-2025-1", "", nil))
}

func TestIsMalicious(t *testing.T) {
	require.True(t, IsMalicious("MAL-2023-462"))
	require.False(t, IsMalicious("CVE-2025-1234"))
	require.False(t, IsMalicious("GHSA-88fw-v6x4-3f58"))
	require.False(t, IsMalicious(""))
}

// A package OSV keeps paging past maxQueryPages has an advisory list truncated
// at the cap: reported incomplete so the reconcile never reads the missing tail
// as "advisory withdrawn" and resolves a still-valid finding as fixed.
func TestQuery_PageCapReportsIncomplete(t *testing.T) {
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Queries []batchQuery `json:"queries"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		n := calls.Add(1)
		fmt.Fprint(w, `{"results":[`)
		for i, q := range body.Queries {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			if q.Package.Name == "endless" {
				fmt.Fprintf(w, `{"vulns":[{"id":"GHSA-%d"}],"next_page_token":"t%d"}`, n, n)
			} else {
				fmt.Fprint(w, `{"vulns":[{"id":"GHSA-small"}]}`)
			}
		}
		fmt.Fprint(w, `]}`)
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"id":%q}`, r.PathValue("id"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	endless := Package{Ecosystem: "npm", Name: "endless", Version: "1.0.0"}
	small := Package{Ecosystem: "npm", Name: "small", Version: "1.0.0"}
	got, incomplete, err := newTestClient(srv).Query(context.Background(), []Package{endless, small})
	require.NoError(t, err)
	require.Equal(t, int32(maxQueryPages), calls.Load(), "the walk stops at the page cap")
	require.Len(t, got[endless], maxQueryPages, "the pages read are still returned")
	require.True(t, incomplete[endless], "a truncated advisory list is a lower bound, not complete")
	require.False(t, incomplete[small], "a package that drained its pages is complete")
}
