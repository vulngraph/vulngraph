package osv

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Distro advisories bundle CVEs: DSA-5611-1 fixes three glibc CVEs, and OSV
// answers a glibc query with it AND the per-CVE DEBIAN-CVE-2023-6246 record
// (both recorded from api.osv.dev, trimmed to the Debian 12 entry). One finding
// per CVE, merged across the two advisories, whatever order they arrive in.
func TestHits_OnePerCVEAcrossDistroAdvisories(t *testing.T) {
	f := &fakeOSV{
		vulnsByPkg: map[string][]string{"Debian:12/glibc@2.36-9": {"DSA-5611-1", "DEBIAN-CVE-2023-6246"}},
		records: map[string]string{
			"DSA-5611-1":           fixture(t, "DSA-5611-1.json"),
			"DEBIAN-CVE-2023-6246": fixture(t, "DEBIAN-CVE-2023-6246.json"),
		},
	}
	glibc := Package{Ecosystem: "Debian:12", Name: "glibc", Version: "2.36-9"}
	got, incomplete, err := newTestClient(f.server(t)).Query(context.Background(), []Package{glibc})
	require.NoError(t, err)
	require.Empty(t, incomplete)
	require.Len(t, got[glibc], 2)

	for _, order := range [][]Vuln{got[glibc], {got[glibc][1], got[glibc][0]}} {
		hits := Hits(order)
		var checks []string
		for _, h := range hits {
			checks = append(checks, h.CheckID)
		}
		require.Equal(t, []string{"CVE-2023-6246", "CVE-2023-6779", "CVE-2023-6780"}, checks,
			"the DSA's upstream also lists DEBIAN-CVE-* ids, which are not check ids")

		first := hits[0]
		require.Equal(t, "DEBIAN-CVE-2023-6246", first.Vuln.ID, "the per-CVE record is the more specific")
		require.Equal(t, []string{"DEBIAN-CVE-2023-6246", "DSA-5611-1"}, first.Advisories)
		require.Equal(t, "DSA-5611-1", hits[1].Vuln.ID)
		require.Equal(t, "2.36-9+deb12u4", hits[1].Vuln.FixedVersion(glibc))

		title, description := hits[1].Describe("glibc")
		require.Equal(t, "CVE-2023-6779 in glibc (DSA-5611-1)", title)
		require.Contains(t, description, "DSA-5611-1 also fixes: CVE-2023-6246, CVE-2023-6779, CVE-2023-6780.")
	}
}

// USN-6450-1 bundles four openssl CVEs (recorded, trimmed to Ubuntu 22.04).
func TestHits_UbuntuNotice(t *testing.T) {
	f := &fakeOSV{
		vulnsByPkg: map[string][]string{"Ubuntu:22.04:LTS/openssl@3.0.2-0ubuntu1.10": {"USN-6450-1"}},
		records:    map[string]string{"USN-6450-1": fixture(t, "USN-6450-1.json")},
	}
	openssl := Package{Ecosystem: "Ubuntu:22.04:LTS", Name: "openssl", Version: "3.0.2-0ubuntu1.10"}
	got, _, err := newTestClient(f.server(t)).Query(context.Background(), []Package{openssl})
	require.NoError(t, err)
	require.Len(t, Hits(got[openssl]), 4)
	require.Equal(t, "CVE-2023-2975", got[openssl][0].CVE(), "CVE() is still the first, for a MAL-* alias")
}

func TestCheckIDs(t *testing.T) {
	tests := []struct {
		name string
		v    Vuln
		want []string
	}{
		{"GHSA with one CVE alias", Vuln{ID: "GHSA-x", Aliases: []string{"CVE-2021-23337"}}, []string{"CVE-2021-23337"}},
		{"no CVE: the advisory id", Vuln{ID: "GHSA-y"}, []string{"GHSA-y"}},
		{"malicious keeps its own id", Vuln{ID: "MAL-2025-41443", Aliases: []string{"CVE-2025-10894"}}, []string{"MAL-2025-41443"}},
		{"aliases then upstream, no repeats", Vuln{ID: "RHSA-1", Aliases: []string{"CVE-1"}, Upstream: []string{"CVE-2", "CVE-1"}}, []string{"CVE-1", "CVE-2"}},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, tt.v.CheckIDs(), tt.name)
	}
}

func TestHits_HighestSeverityWins(t *testing.T) {
	hits := Hits([]Vuln{
		{ID: "DSA-1", Upstream: []string{"CVE-1", "CVE-2"}, Severity: finding.SeverityCritical},
		{ID: "DEBIAN-CVE-1", Upstream: []string{"CVE-1"}, Severity: finding.SeverityLow},
	})
	require.Len(t, hits, 2)
	require.Equal(t, finding.SeverityCritical, hits[0].Severity)
	require.Equal(t, "DEBIAN-CVE-1", hits[0].Vuln.ID)
	require.Equal(t, "DEBIAN-CVE-1,DSA-1", hits[0].Advisory())
}
