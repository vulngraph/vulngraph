package distro

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRelease(t *testing.T) {
	for in, want := range map[string]string{
		"Ubuntu:22.04:LTS":   "22.04",
		"Ubuntu:23.10":       "23.10",
		"Debian:12":          "12",
		"Debian":             "",
		"openSUSE:Leap 15.5": "15.5",
		"SUSE:15.5":          "15.5",
		"Amazon Linux:2023":  "2023",
		"Red Hat:9":          "9",
	} {
		require.Equal(t, want, Release(in), in)
	}
}

func TestFamilyOf(t *testing.T) {
	f, ok := FamilyOf("Amazon Linux:2023")
	require.True(t, ok)
	require.Equal(t, SourceALAS, f.Source)

	f, ok = FamilyOf("Oracle Linux:9")
	require.True(t, ok)
	require.Equal(t, SourceELSA, f.Source)

	f, ok = FamilyOf("CentOS:7")
	require.True(t, ok)
	require.Empty(t, f.Source)
	require.NotEmpty(t, f.NoSourceReason, "a family without a source must say why, for the coverage report")

	_, ok = FamilyOf("npm")
	require.False(t, ok, "language ecosystems are not distributions")
}

func TestMatchedByOSV(t *testing.T) {
	for eco, want := range map[string]bool{
		"npm":                true,
		"Go":                 true,
		"Debian:12":          true,
		"Red Hat:9":          true,
		"Rocky Linux:9":      true,
		"openSUSE:Leap 15.6": true,
		"Amazon Linux:2023":  false, // ALAS, from the package node
		"Oracle Linux:9":     false, // ELSA, from the package node
		"CentOS:7":           false, // nothing
	} {
		require.Equal(t, want, MatchedByOSV(eco), eco)
	}
}

// OSV keys Debian, Ubuntu, Alpine, Rocky and SUSE by source package: libssl3 in
// "Ubuntu:22.04:LTS" returns 0 advisories where openssl returns 66 (live,
// 2026-10-07). The source version wins when the binary's differs (binNMU,
// separately-versioned binaries).
func TestAdvisoryQuery(t *testing.T) {
	tests := []struct {
		name                           string
		eco, bin, ver, srcName, srcVer string
		wantName, wantVer              string
	}{
		{"debian binary asked by its source", "Debian:12", "libssl3", "3.0.11-1~deb12u2", "openssl", "", "openssl", "3.0.11-1~deb12u2"},
		{"binNMU asked at the source version", "Debian:12", "libfoo1", "1.2-3+b1", "foo", "1.2-3", "foo", "1.2-3"},
		{"separately versioned binary", "Debian:12", "gcc", "4:12.2.0-3", "gcc-defaults", "1.203", "gcc-defaults", "1.203"},
		{"ubuntu", "Ubuntu:22.04:LTS", "libssl3", "3.0.2-0ubuntu1.10", "openssl", "", "openssl", "3.0.2-0ubuntu1.10"},
		{"alpine origin", "Alpine:v3.18", "libcrypto3", "3.1.0-r0", "openssl", "", "openssl", "3.1.0-r0"},
		{"suse", "SUSE:15.5", "libopenssl3", "3.0.8-150500.5.1", "openssl-3", "", "openssl-3", "3.0.8-150500.5.1"},
		{"rocky", "Rocky Linux:9", "openssl-libs", "3.0.7-24.el9", "openssl", "", "openssl", "3.0.7-24.el9"},
		{"red hat is binary-keyed", "Red Hat:9", "openssl-libs", "1:3.0.7-24.el9", "openssl", "", "openssl-libs", "1:3.0.7-24.el9"},
		{"no source name: the binary is all there is", "Debian:12", "libssl3", "3.0.11-1", "", "", "libssl3", "3.0.11-1"},
		{"language ecosystem", "npm", "lodash", "4.17.20", "x", "y", "lodash", "4.17.20"},
	}
	for _, tt := range tests {
		name, ver := AdvisoryQuery(tt.eco, tt.bin, tt.ver, tt.srcName, tt.srcVer)
		require.Equal(t, tt.wantName, name, tt.name)
		require.Equal(t, tt.wantVer, ver, tt.name)
	}
}

// Every family with no advisory source explains itself, and the list is stable.
func TestFamilies(t *testing.T) {
	fams := Families()
	require.NotEmpty(t, fams)
	for i, f := range fams {
		if f.Source == "" {
			require.NotEmpty(t, f.NoSourceReason, f.Name)
		}
		if i > 0 {
			require.Less(t, fams[i-1].Name, f.Name, "sorted by name")
		}
	}
}
