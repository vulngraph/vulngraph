package updateinfo

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// The fixtures are trimmed copies of the live files (descriptions elided),
// recorded 2026-10-07 from cdn.amazonlinux.com and yum.oracle.com.
func parseFixture(t *testing.T, name string) []Advisory {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	advs, err := Parse(f)
	require.NoError(t, err)
	return advs
}

func byID(advs []Advisory) map[string]Advisory {
	out := map[string]Advisory{}
	for _, a := range advs {
		out[a.ID] = a
	}
	return out
}

func TestParse_AmazonLinux2(t *testing.T) {
	advs := byID(parseFixture(t, "al2-updateinfo.xml"))
	require.Len(t, advs, 2)

	a := advs["ALAS2-2026-3907"]
	require.Equal(t, finding.SeverityHigh, a.Severity, "ALAS 'important' is High")
	require.Equal(t, []string{"CVE-2026-54874", "CVE-2026-63072"}, a.CVEs)
	require.Equal(t, "1:1.1.1zi-1.amzn2.0.1", a.Fixed["openssl11-libs"], "epoch kept, one entry across x86_64/i686/aarch64")
	require.Equal(t, time.Date(2026, 9, 14, 9, 0, 0, 0, time.UTC), a.Issued)

	k := advs["ALAS2-2018-939"]
	require.Equal(t, finding.SeverityCritical, k.Severity)
	require.Equal(t, "4.9.76-38.79.amzn2", k.Fixed["kernel"], "a zero epoch is dropped, as the inventory producers drop it")
}

// Recorded from the live kernel channels (2026-10-09): the AL2 kernel-5.10
// extras topic and Oracle Linux 8 UEKR6.
func TestParse_KernelChannels(t *testing.T) {
	al2 := byID(parseFixture(t, "al2-kernel-5.10-updateinfo.xml"))["ALAS2KERNEL-5.10-2026-132"]
	require.Equal(t, "5.10.268-266.1092.amzn2", al2.Fixed["kernel"])
	require.Equal(t, "5.10.268-266.1092.amzn2", al2.Fixed["bpftool"], "the line's tools share its version")
	require.NotEmpty(t, al2.CVEs)

	uek := byID(parseFixture(t, "ol8-uekr6-updateinfo.xml"))["ELSA-2025-20190"]
	require.Equal(t, "5.4.17-2136.341.3.3.el8uek", uek.Fixed["kernel-uek"])
	require.Equal(t, []string{"CVE-2024-39494", "CVE-2024-57892"}, uek.CVEs)
}

func TestOnStream(t *testing.T) {
	for _, tc := range []struct {
		evr, stream string
		want        bool
	}{
		{"5.10.268-266.1092.amzn2", "5.10", true},
		{"0:5.10.268-266.1092.amzn2", "5.10", true},
		{"5.15.0-200.el8uek", "5.15", true},
		{"5.4.17-2136.el8uek", "5.15", false},
		{"5.4.17-2136.el8uek", "5.4", true},
		{"5.40.1-1", "5.4", false},
		{"4.14.355-275.570.amzn2", "5.10", false},
	} {
		require.Equal(t, tc.want, OnStream(tc.evr, tc.stream), "%s on %s", tc.evr, tc.stream)
	}
}

// A stream channel's advisories keep only fixes on the line and are marked
// with it; an off-line fix (a dtrace build in a UEK channel) is dropped rather
// than matched against the core repository's build of the same name.
func TestScopeToStream(t *testing.T) {
	got := ScopeToStream([]Advisory{
		{ID: "ELSA-1", Fixed: map[string]string{"kernel-uek": "5.4.17-2136.el8uek", "dtrace": "2.0.1-1.el8"}},
		{ID: "ELSA-2", Fixed: map[string]string{"dtrace": "2.0.2-1.el8"}},
	}, "5.4")
	require.Len(t, got, 1)
	require.Equal(t, "5.4", got[0].Stream)
	require.Equal(t, map[string]string{"kernel-uek": "5.4.17-2136.el8uek"}, got[0].Fixed)
}

func TestParse_AmazonLinux2023(t *testing.T) {
	advs := byID(parseFixture(t, "al2023-updateinfo.xml"))
	a := advs["ALAS2023-2026-2136"]
	require.Equal(t, finding.SeverityHigh, a.Severity, "AL2023 capitalises its ratings")
	require.Len(t, a.CVEs, 9)
	require.Equal(t, "1:3.5.8-1.amzn2023.0.1", a.Fixed["openssl-libs"])
	require.Equal(t, finding.SeverityHigh, advs["ALAS2023-2023-001"].Severity)
}

func TestParse_OracleLinux(t *testing.T) {
	advs := byID(parseFixture(t, "ol9-updateinfo.xml"))
	require.Len(t, advs, 1, "the ELBA bugfix advisory is not a security advisory")
	a := advs["ELSA-2024-9333"]
	require.Equal(t, finding.SeverityLow, a.Severity)
	require.Equal(t, []string{"CVE-2024-2511", "CVE-2024-4603", "CVE-2024-4741", "CVE-2024-5535"}, a.CVEs)
	require.Equal(t, "1:3.2.2-6.0.1.el9_5", a.Fixed["openssl"])
	require.Equal(t, "3.0.7-6.0.1.el9_5", a.Fixed["openssl-fips-provider"])
}

func TestParse_SkipsSourceRPMsAndEmptyAdvisories(t *testing.T) {
	doc := `<updates>
<update type="security"><id>X-1</id><severity>low</severity>
<pkglist><collection><package name="foo" version="1.0" release="1" epoch="0" arch="src"/></collection></pkglist></update>
<update type="security"><id>X-2</id><severity>moderate</severity>
<references><reference id="CVE-2026-1" type="cve"/><reference id="CVE-2026-1" type="cve"/><reference id="X-2" type="self"/></references>
<pkglist><collection>
<package name="foo" version="1.0" release="1" epoch="0" arch="src"/>
<package name="foo-libs" version="1.0" release="2" epoch="0" arch="x86_64"/>
<package name="foo-libs" version="1.0" release="3" epoch="0" arch="aarch64"/>
</collection></pkglist></update>
</updates>`
	advs, err := Parse(strings.NewReader(doc))
	require.NoError(t, err)
	require.Len(t, advs, 1, "an advisory listing only source rpms matches no installed binary")
	require.Equal(t, "X-2", advs[0].ID)
	require.Equal(t, finding.SeverityMedium, advs[0].Severity, "Oracle 'moderate' is Medium")
	require.Equal(t, []string{"CVE-2026-1"}, advs[0].CVEs, "deduped, self references dropped")
	require.Equal(t, map[string]string{"foo-libs": "1.0-3"}, advs[0].Fixed, "the highest build across architectures")
}

func TestParse_MalformedIsAnError(t *testing.T) {
	_, err := Parse(strings.NewReader(`<updates><update type="security"><id>X</id>`))
	require.Error(t, err, "a truncated document must not read as a short advisory list")
}

func TestMapSeverity(t *testing.T) {
	for in, want := range map[string]finding.Severity{
		"critical": finding.SeverityCritical, "Critical": finding.SeverityCritical,
		"important": finding.SeverityHigh, "Important": finding.SeverityHigh,
		"medium": finding.SeverityMedium, "Moderate": finding.SeverityMedium,
		"low": finding.SeverityLow, "": finding.SeverityMedium,
	} {
		require.Equal(t, want, MapSeverity(in), in)
	}
}

func TestEVR(t *testing.T) {
	require.Equal(t, "1:3.0.7-27.el9", EVR("1", "3.0.7", "27.el9"))
	require.Equal(t, "3.0.7-27.el9", EVR("0", "3.0.7", "27.el9"))
	require.Equal(t, "3.0.7-27.el9", EVR("", "3.0.7", "27.el9"))
	require.Equal(t, "3.0.7", EVR("", "3.0.7", ""))
}

func TestMerge(t *testing.T) {
	baseos := []Advisory{{ID: "ELSA-1", CVEs: []string{"CVE-1"}, Fixed: map[string]string{"a": "1.0-1"}}}
	appstream := []Advisory{
		{ID: "ELSA-1", CVEs: []string{"CVE-2", "CVE-1"}, Fixed: map[string]string{"b": "2.0-1", "a": "1.0-2"}},
		{ID: "ELSA-2", Fixed: map[string]string{"c": "1-1"}},
	}
	got := byID(merge(baseos, appstream))
	require.Len(t, got, 2)
	require.Equal(t, map[string]string{"a": "1.0-2", "b": "2.0-1"}, got["ELSA-1"].Fixed)
	require.Equal(t, []string{"CVE-1", "CVE-2"}, got["ELSA-1"].CVEs)
	require.Equal(t, map[string]string{"a": "1.0-1"}, baseos[0].Fixed, "merge must not mutate its inputs")
}

// One advisory id read from two kernel lines stays two advisories, each scoped
// to its own line: merged, the 5.15 fix would be held against 5.4 installs.
func TestMerge_KeepsStreamsApart(t *testing.T) {
	uek6 := []Advisory{{ID: "ELSA-9", Stream: "5.4", Fixed: map[string]string{"kernel-uek": "5.4.17-2136.el8uek"}}}
	uek7 := []Advisory{{ID: "ELSA-9", Stream: "5.15", Fixed: map[string]string{"kernel-uek": "5.15.0-300.el8uek"}}}
	got := merge(uek6, uek7)
	require.Len(t, got, 2)
	for _, a := range got {
		for _, evr := range a.Fixed {
			require.True(t, OnStream(evr, a.Stream), "%s carries only its own line's fix", a.Stream)
		}
	}
}
