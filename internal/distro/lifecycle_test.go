package distro

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEndOfLife(t *testing.T) {
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		ecosystem string
		known     bool
		past      bool
		final     bool
	}{
		{"CentOS:7", true, true, true},
		{"CentOS:8", true, true, true},
		{"CentOS:10", true, false, true},
		{"Amazon Linux:2", true, true, true},
		{"Amazon Linux:1", true, true, true},
		{"Amazon Linux:2023", true, false, true},
		{"Red Hat:7", true, true, false},
		{"Red Hat:9", true, false, false},
		{"Red Hat:10", true, false, false},
		{"Ubuntu:18.04:LTS", true, true, false},
		{"Ubuntu:24.04:LTS", true, false, false},
		{"Ubuntu:26.04:LTS", true, false, false},
		{"Ubuntu:24.10", true, true, true},
		{"Ubuntu:25.10", true, true, true},
		{"Debian:10", true, true, true},
		{"Debian:11", true, true, true}, // LTS ended 2026-08-31
		{"Debian:12", true, false, true},
		{"Debian:13", true, false, true},
		{"Oracle Linux:7", true, true, false},
		{"Rocky Linux:8", true, false, false},
		{"AlmaLinux:9", true, false, false},
		// Alpine's coordinate keeps OSV's "v" prefix ("Alpine:v3.20").
		{"Alpine:v3.18", true, true, true},
		{"Alpine:v3.20", true, true, true},
		{"Alpine:v3.22", true, false, true},
		{"SUSE:15.5", true, true, false},
		{"SUSE:15.7", true, false, false},
		{"openSUSE:Leap 15.5", true, true, true},
		{"openSUSE:Leap 16.0", true, false, true},
		// Unlisted is unknown, never "supported".
		{"Ubuntu:12.04:LTS", false, false, false},
		{"openSUSE:Tumbleweed", false, false, false},
		{"Alpine", false, false, false},
		{"Alpine:3.20", false, false, false}, // not OSV's spelling
		{"npm", false, false, false},
	}
	for _, tt := range tests {
		l, ok := EndOfLife(tt.ecosystem)
		require.Equal(t, tt.known, ok, tt.ecosystem)
		require.Equal(t, tt.past, l.Past(now), tt.ecosystem)
		require.Equal(t, tt.final, l.Final, tt.ecosystem)
	}
}

// Every lifecycle family is a known family, so the EOL check and the coverage
// report cannot name a distribution the rest of the registry does not know.
func TestLifecycleFamiliesAreKnown(t *testing.T) {
	for name := range lifecycles {
		_, ok := families[name]
		require.True(t, ok, name)
	}
}

func TestLifecycleEcosystems(t *testing.T) {
	ecos := LifecycleEcosystems()
	require.Contains(t, ecos, "CentOS:7")
	require.Contains(t, ecos, "Ubuntu:18.04")
	require.Contains(t, ecos, "Alpine:v3.20")
	for _, e := range ecos {
		_, ok := EndOfLife(e)
		require.True(t, ok, "every listed coordinate resolves: %s", e)
	}
}

func TestLatestSupported(t *testing.T) {
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		family string
		want   string
		ok     bool
	}{
		{"Debian", "13", true},
		{"Ubuntu", "26.04", true}, // the newest LTS outlives every interim
		{"Alpine", "v3.24", true},
		{"Amazon Linux", "2023", true},
		{"Red Hat", "10", true},
		{"Rocky Linux", "10", true},
		{"SUSE", "15.7", true},
		{"openSUSE", "16.0", true},
		{"npm", "", false},
	}
	for _, tt := range tests {
		got, ok := LatestSupported(tt.family, now)
		require.Equal(t, tt.ok, ok, tt.family)
		require.Equal(t, tt.want, got, tt.family)
	}

	_, ok := LatestSupported("Debian", time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC))
	require.False(t, ok, "every release past its end: no target, never the least-dead one")
}
