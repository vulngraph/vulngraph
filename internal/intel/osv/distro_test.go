package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// fixture reads a trimmed real OSV record recorded from api.osv.dev/v1/vulns.
func fixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return string(raw)
}

// A RHEL 9 host is queried by the bare "Red Hat" family, which OSV matches
// across every stream — so the RHEL 10 advisory comes back too, and only the
// RHEL 9 one may survive.
func TestQuery_RedHat_KeepsOnlyTheHostsRelease(t *testing.T) {
	rhsa, rhba := fixture(t, "RHSA-2024_2447.json"), fixture(t, "RHBA-2025_6314.json")
	f := &fakeOSV{
		vulnsByPkg: map[string][]string{
			"Red Hat/openssl-libs@1:3.0.7-24.el9": {"RHSA-2024:2447", "RHBA-2025:6314"},
			"Red Hat/openssl-libs@1:3.0.7-27.el9": {"RHSA-2024:2447", "RHBA-2025:6314"}, // patched for 9, still "affected" by 10's fix
			"Red Hat/openssl@1:3.2.2-1.el10":      {"RHBA-2025:6314"},
		},
		records: map[string]string{"RHSA-2024:2447": rhsa, "RHBA-2025:6314": rhba},
	}
	c := newTestClient(f.server(t))
	vulnerable := Package{Ecosystem: "Red Hat:9", Name: "openssl-libs", Version: "1:3.0.7-24.el9"}
	patched := Package{Ecosystem: "Red Hat:9", Name: "openssl-libs", Version: "1:3.0.7-27.el9"}
	rhel10 := Package{Ecosystem: "Red Hat:10", Name: "openssl", Version: "1:3.2.2-1.el10"}

	got, incomplete, err := c.Query(context.Background(), []Package{vulnerable, patched, rhel10})
	require.NoError(t, err)
	require.Empty(t, incomplete)

	require.Len(t, got[vulnerable], 1, "RHBA-2025:6314 fixes RHEL 10 only")
	v := got[vulnerable][0]
	require.Equal(t, "RHSA-2024:2447", v.ID)
	require.Equal(t, "CVE-2023-2975", v.CVE())
	require.Equal(t, "1:3.0.7-27.el9", v.FixedVersion(vulnerable), "the RHEL 9 fix, not RHEL 10's")

	require.Empty(t, got[patched], "at the fixed version, the RHEL 9 entry no longer holds it")

	require.Len(t, got[rhel10], 1, "RHEL 10 streams are minor-scoped (enterprise_linux:10.0)")
	require.Equal(t, "1:3.2.2-16.el10", got[rhel10][0].FixedVersion(rhel10))
}

// SUSE is keyed by product and service pack; a SLES 15 SP5 host matches every
// product of that service pack and none of another.
func TestQuery_SUSE_MatchesServicePack(t *testing.T) {
	rec := fixture(t, "SUSE-SU-2023_2620-1.json")
	f := &fakeOSV{
		vulnsByPkg: map[string][]string{
			"SUSE/openssl-3@3.0.8-150500.5.1":               {"SUSE-SU-2023:2620-1"},
			"SUSE/openssl-3@3.0.8-150400.4.1":               {"SUSE-SU-2023:2620-1"},
			"openSUSE:Leap 15.5/openssl-3@3.0.8-150500.5.1": {"SUSE-SU-2023:2620-1"},
		},
		records: map[string]string{"SUSE-SU-2023:2620-1": rec},
	}
	c := newTestClient(f.server(t))
	sp5 := Package{Ecosystem: "SUSE:15.5", Name: "openssl-3", Version: "3.0.8-150500.5.1"}
	sp4 := Package{Ecosystem: "SUSE:15.4", Name: "openssl-3", Version: "3.0.8-150400.4.1"}
	leap := Package{Ecosystem: "openSUSE:Leap 15.5", Name: "openssl-3", Version: "3.0.8-150500.5.1"}

	got, _, err := c.Query(context.Background(), []Package{sp5, sp4, leap})
	require.NoError(t, err)
	require.Len(t, got[sp5], 1)
	require.Equal(t, "CVE-2023-1255", got[sp5][0].CVE())
	require.Equal(t, "3.0.8-150500.5.3.1", got[sp5][0].FixedVersion(sp5))
	require.Empty(t, got[sp4], "the advisory lists no 15 SP4 product")
	require.Len(t, got[leap], 1, "openSUSE Leap is a real OSV ecosystem, matched verbatim")
	require.Equal(t, "3.0.8-150500.5.3.1", got[leap][0].FixedVersion(leap))
}

// One query naming an ecosystem OSV does not serve fails the WHOLE batch with a
// 400. Such packages are never sent, and are reported incomplete, not clean.
func TestQuery_UnsupportedEcosystemExcludedPerPackage(t *testing.T) {
	f := &fakeOSV{
		vulnsByPkg: map[string][]string{"npm/lodash@4.17.20": {"GHSA-35jh-r3h4-6jhm"}},
		records:    map[string]string{"GHSA-35jh-r3h4-6jhm": lodashGHSA},
	}
	c := newTestClient(f.server(t))
	lodash := Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	amzn := Package{Ecosystem: "Amazon Linux:2", Name: "openssl-libs", Version: "1:1.0.2k-24.amzn2.0.4"}
	centos := Package{Ecosystem: "CentOS:7", Name: "bash", Version: "4.2.46-34.el7"}

	got, incomplete, err := c.Query(context.Background(), []Package{lodash, amzn, centos})
	require.NoError(t, err)
	require.Len(t, got[lodash], 1)
	require.True(t, incomplete[amzn])
	require.True(t, incomplete[centos])
	require.False(t, incomplete[lodash])
}

// If OSV drops a family the snapshot still lists, its 400 names the offending
// query; that package is excluded and the batch retried, not the refresh lost.
func TestQuery_InvalidEcosystem400IsRetriedWithoutThePackage(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body struct {
			Queries []batchQuery `json:"queries"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		for i, q := range body.Queries {
			if q.Package.Ecosystem == "Mageia:9" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, `{"code":3,"message":"error in query at index %d: rpc error: code = InvalidArgument desc = invalid ecosystem"}`, i)
				return
			}
		}
		fmt.Fprint(w, `{"results":[`)
		for i := range body.Queries {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprint(w, `{"vulns":[{"id":"GHSA-35jh-r3h4-6jhm"}]}`)
		}
		fmt.Fprint(w, `]}`)
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, lodashGHSA) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	lodash := Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	dropped := Package{Ecosystem: "Mageia:9", Name: "openssl", Version: "3.0.1-1.mga9"}
	got, incomplete, err := newTestClient(srv).Query(context.Background(), []Package{dropped, lodash})
	require.NoError(t, err)
	require.Equal(t, 2, calls, "one rejected call, one retry")
	require.Len(t, got[lodash], 1)
	require.True(t, incomplete[dropped])
	require.Empty(t, got[dropped])
}

func TestParseInvalidQuery(t *testing.T) {
	inv := parseInvalidQuery([]byte(`{"code":3,"message":"error in query at index 12: rpc error: code = InvalidArgument desc = invalid ecosystem"}`))
	require.NotNil(t, inv)
	require.Equal(t, 12, inv.index)
	require.Nil(t, parseInvalidQuery([]byte(`{"code":3,"message":"invalid version"}`)))
	require.Nil(t, parseInvalidQuery([]byte(`not json`)))
}

func TestSupported(t *testing.T) {
	for eco, want := range map[string]bool{
		"Debian:12": true, "Ubuntu:22.04:LTS": true, "Red Hat:9": true, "SUSE:15.5": true,
		"openSUSE:Leap 15.5": true, "Rocky Linux:9": true, "npm": true,
		"Amazon Linux:2": false, "Oracle Linux:9": false, "CentOS:7": false, "": false,
	} {
		require.Equal(t, want, Supported(eco), eco)
	}
}

func TestSUSEProductMatching(t *testing.T) {
	require.Equal(t, "15 SP5", suseToken("15.5"))
	require.Equal(t, "15", suseToken("15"))
	require.Equal(t, "12", suseToken("12.0"))
	require.Equal(t, "16.0", suseToken("16.0"))

	for _, tt := range []struct {
		affected, token string
		want            bool
	}{
		{"SUSE:Linux Enterprise Server 15 SP5", "15 SP5", true},
		{"SUSE:Linux Enterprise Module for Basesystem 15 SP5", "15 SP5", true},
		{"SUSE:Linux Enterprise Server 15 SP5-LTSS", "15 SP5", true},
		{"SUSE:Linux Enterprise Server 15 SP5", "15 SP4", false},
		{"SUSE:Linux Enterprise Server 15 SP5", "15", false},
		{"SUSE:Linux Enterprise Server 15", "15", true},
		{"SUSE:Linux Enterprise Server 16.0", "16.0", true},
		{"openSUSE:Leap 15.5", "15 SP5", false},
	} {
		require.Equal(t, tt.want, suseProductMatches(tt.affected, tt.token), "%s / %s", tt.affected, tt.token)
	}
}

func TestRPMRangeContains(t *testing.T) {
	ev := func(kind, v string) rangeEvent {
		switch kind {
		case "i":
			return rangeEvent{Introduced: v}
		case "f":
			return rangeEvent{Fixed: v}
		}
		return rangeEvent{LastAffected: v}
	}
	tests := []struct {
		name    string
		events  []rangeEvent
		version string
		want    bool
	}{
		{"below fix", []rangeEvent{ev("i", "0"), ev("f", "1:3.0.7-27.el9")}, "1:3.0.7-24.el9", true},
		{"at fix", []rangeEvent{ev("i", "0"), ev("f", "1:3.0.7-27.el9")}, "1:3.0.7-27.el9", false},
		{"above fix", []rangeEvent{ev("i", "0"), ev("f", "1:3.0.7-27.el9")}, "1:3.0.7-28.el9", false},
		{"epoch decides", []rangeEvent{ev("i", "0"), ev("f", "1:3.0.7-27.el9")}, "3.5.0-1.el9", true},
		{"events out of order", []rangeEvent{ev("f", "2.0-1"), ev("i", "1.0-1")}, "1.5-1", true},
		{"before introduced", []rangeEvent{ev("i", "1.0-1"), ev("f", "2.0-1")}, "0.9-1", false},
		{"no fix published", []rangeEvent{ev("i", "0")}, "9.9-9", true},
		{"at last_affected", []rangeEvent{ev("i", "0"), ev("l", "2.0-1")}, "2.0-1", true},
		{"past last_affected", []rangeEvent{ev("i", "0"), ev("l", "2.0-1")}, "2.0-2", false},
		{"reintroduced", []rangeEvent{ev("i", "0"), ev("f", "2.0-1"), ev("i", "3.0-1"), ev("f", "3.0-5")}, "3.0-2", true},
		{"between ranges", []rangeEvent{ev("i", "0"), ev("f", "2.0-1"), ev("i", "3.0-1"), ev("f", "3.0-5")}, "2.5-1", false},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, rpmRangeContains(tt.events, tt.version), tt.name)
	}
}
