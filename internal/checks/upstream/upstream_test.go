package upstream

import (
	"io/fs"
	"os"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
)

// fixtureBenchmarks are matrices shaped to exercise every report branch
// against testdata/bundle: a newer version upstream, added and removed IDs,
// a nearest-version (non-exact) source, and new FSBP controls.
func fixtureBenchmarks() []benchmarks.Benchmark {
	m := func(id, version string, ids ...string) benchmarks.Benchmark {
		b := benchmarks.Benchmark{ID: id, Name: id, Version: version}
		for _, c := range ids {
			b.Controls = append(b.Controls, benchmarks.Control{ID: c})
		}
		return b
	}
	return []benchmarks.Benchmark{
		m("aws-fsbp", "1.0.0", "ACM.1", "Old.1"),
		m("cis-aws-foundations", "7.0.0", "1.1", "1.2", "1.3"),
		m("cis-azure-foundations", "6.0.0", "2.1"),
		m("cis-aks", "1.8.0", "2.1.1"),
		m("cis-eks", "1.8.0", "3.1.1", "3.1.10"),
		m("cis-gcp-foundation", "5.0.0", "3.1"),
		m("cis-gke", "2.0.0", "5.10.1"),
		m("cis-kubernetes", "2.0.1", "1.1.1"),
	}
}

func bundle() fs.FS { return os.DirFS("testdata/bundle") }

// TestWantedDrivesFetchRounds replays a fetch: starting from nothing, each
// round asks only for paths the previous round made nameable, and the
// fixed point is exactly the recorded bundle — nothing fetched that the diff
// does not read.
func TestWantedDrivesFetchRounds(t *testing.T) {
	src := bundle()
	mem := fstest.MapFS{}
	for round := 0; round < 6; round++ {
		want, err := Wanted(mem, fixtureBenchmarks(), false)
		require.NoError(t, err)
		if len(want) == 0 {
			break
		}
		for _, p := range want {
			raw, err := fs.ReadFile(src, p)
			require.NoError(t, err, "round %d asked for %s, which the recorded bundle lacks", round, p)
			mem[p] = &fstest.MapFile{Data: raw}
		}
	}
	var recorded []string
	require.NoError(t, fs.WalkDir(src, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			recorded = append(recorded, p)
		}
		return err
	}))
	var fetched []string
	for p := range mem {
		fetched = append(fetched, p)
	}
	require.ElementsMatch(t, recorded, fetched)
}

func TestWantedSkipsReferencePageWhenAPIListed(t *testing.T) {
	mem := fstest.MapFS{PathSecurityHubAPI: &fstest.MapFile{Data: []byte(`{}`)}}
	want, err := Wanted(mem, fixtureBenchmarks(), false)
	require.NoError(t, err)
	require.NotContains(t, want, PathSecurityHubReference)
}

func observeFixture(t *testing.T) []Observation {
	t.Helper()
	obs, err := Observe(bundle(), fixtureBenchmarks())
	require.NoError(t, err)
	return obs
}

func reportFor(t *testing.T, rep Report, id string) BenchmarkReport {
	t.Helper()
	for _, r := range rep.Benchmarks {
		if r.Benchmark == id {
			return r
		}
	}
	t.Fatalf("no report for %s", id)
	return BenchmarkReport{}
}

func snapshotsOf(obs []Observation) map[string]benchmarks.SourceSnapshot {
	out := map[string]benchmarks.SourceSnapshot{}
	for _, o := range obs {
		out[o.Benchmark] = Snapshot(o, "2026-10-01")
	}
	return out
}

func TestDiffReportsEachKindOfDrift(t *testing.T) {
	obs := observeFixture(t)
	rep := Diff(fixtureBenchmarks(), obs, snapshotsOf(obs), nil, "2026-10-10")
	require.True(t, rep.Drift)

	aws := reportFor(t, rep, "cis-aws-foundations")
	require.True(t, aws.Exact)
	require.Equal(t, "7.0", aws.SourceVersion)
	require.True(t, aws.NewerVersion, "Prowler publishes cis_8.0_aws.json")
	require.Equal(t, "8.0", aws.Latest)
	require.Equal(t, []Control{{ID: "1.4"}}, aws.Added)
	require.Equal(t, []string{"1.3"}, aws.Removed)
	require.True(t, aws.Drift)

	fsbp := reportFor(t, rep, "aws-fsbp")
	require.Equal(t, []Control{{ID: "Bedrock.1", Title: "Amazon Bedrock data sources should be encrypted with customer managed AWS KMS keys"}}, fsbp.Added,
		"new FSBP controls carry AWS's title; Account.2 is NIST-only and not FSBP")
	require.Equal(t, []string{"Old.1"}, fsbp.Removed)

	gke := reportFor(t, rep, "cis-gke")
	require.False(t, gke.Exact, "kube-bench has no gke-2.0.0")
	require.Equal(t, "1.9.0", gke.SourceVersion)
	require.Equal(t, []Control{{ID: "5.10.4"}}, gke.Added)
	require.False(t, gke.Drift, "a nearest-version delta is informational, not drift")

	for _, id := range []string{"cis-azure-foundations", "cis-gcp-foundation", "cis-eks", "cis-kubernetes"} {
		r := reportFor(t, rep, id)
		require.Falsef(t, r.Drift, "%s matches its upstream", id)
		require.False(t, r.NewerVersion, "%s: older or differently numbered versions are not newer (azure-policy v3, kube-bench cis-1.24)", id)
	}
	require.Contains(t, rep.Text(), "new FSBP controls: Bedrock.1")
}

func TestDiffSnapshotStaleIsDrift(t *testing.T) {
	obs := observeFixture(t)
	snaps := snapshotsOf(obs)
	s := snaps["cis-gcp-foundation"]
	s.ControlIDs = []string{"3.1", "3.2"}
	snaps["cis-gcp-foundation"] = s
	r := reportFor(t, Diff(fixtureBenchmarks(), obs, snaps, nil, "d"), "cis-gcp-foundation")
	require.True(t, r.SnapshotStale)
	require.True(t, r.Drift, "a stale snapshot means the completeness test checks an old list")
}

func TestDiffUnreadUpstreamIsDrift(t *testing.T) {
	rep := Diff(fixtureBenchmarks(), nil, nil, nil, "d")
	require.True(t, rep.Drift)
	require.Equal(t, "unread", reportFor(t, rep, "cis-eks").Source)
}

func TestDiffMarksAcknowledged(t *testing.T) {
	obs := observeFixture(t)
	acks := map[string]benchmarks.Acknowledgement{"aws-fsbp": {NotInSource: map[string]string{"Old.1": "retired"}}}
	r := reportFor(t, Diff(fixtureBenchmarks(), obs, snapshotsOf(obs), acks, "d"), "aws-fsbp")
	require.Equal(t, map[string]string{"Old.1": "retired"}, r.Acknowledged)
	require.True(t, r.Drift, "acknowledged differences stay drift until reconciled")
}

func TestObserveSecurityHubPrefersAPI(t *testing.T) {
	mem := fstest.MapFS{PathSecurityHubAPI: &fstest.MapFile{Data: []byte(
		`{"SecurityControlDefinitions":[{"SecurityControlId":"ACM.1","Title":"t"},{"SecurityControlId":"S3.1","Title":"u"}]}`)}}
	o, err := observeSecurityHub(mem, benchmarks.Benchmark{ID: "aws-fsbp", Version: "1.0.0"})
	require.NoError(t, err)
	require.Equal(t, []string{"ACM.1", "S3.1"}, o.IDs())
	require.Contains(t, o.Source, "ListSecurityControlDefinitions")
}

func TestObserveRefusesDegradedPayloads(t *testing.T) {
	_, err := githubListing([]byte(`{"message":"API rate limit exceeded"}`))
	require.ErrorContains(t, err, "rate limit", "an API error is not an empty directory")
	_, err = githubListing([]byte(`[]`))
	require.Error(t, err)
	_, err = decodeProwler([]byte(`{"Framework":"CIS","Requirements":[]}`))
	require.Error(t, err, "a file with no requirements is a broken fetch")
	_, err = securityHubReferenceFSBP([]byte(`<html>moved</html>`))
	require.Error(t, err, "a page with no control rows changed layout; it does not mean FSBP is empty")
	_, err = securityHubAPIControls([]byte(`{"SecurityControlDefinitions":[]}`))
	require.Error(t, err)
}

func TestKubeBenchIDsKeepScalarText(t *testing.T) {
	ids, err := kubeBenchIDs([]byte("groups:\n  - id: 5\n    checks:\n      - id: 5.10\n      - id: 5.1\n"))
	require.NoError(t, err)
	require.Equal(t, []string{"5.10", "5.1"}, ids, "5.10 must not decode as the float 5.1")
}

func TestVersions(t *testing.T) {
	require.True(t, sameVersion("7.0", "7.0.0"))
	require.False(t, sameVersion("7.1", "7.0.0"))
	require.Equal(t, "1.10", newest([]string{"1.8", "1.10", "1.9"}))
	require.Equal(t, "1.9.0", nearestAtMost([]string{"1.8.0", "1.9.0", "2.1.0"}, "2.0.0"))
	require.Equal(t, "", nearestAtMost([]string{"3.0"}, "2.0.0"))
	require.Equal(t, []string{"1.4.0", "2.0.0", "3.0.0"},
		azurePolicyCISVersions([]string{"CISv1_4_0.json", "CISv2_0_0.json", "CIS_Azure_Foundations_v3.0.0.json", "CIS_Controls_v8.1.json"}))
}

func TestNaturalLess(t *testing.T) {
	require.True(t, NaturalLess("A.5.9", "A.5.10"))
	require.True(t, NaturalLess("AC-2(3)", "AC-2(12)"))
	require.True(t, NaturalLess("AC-2", "AC-2(1)"))
	require.True(t, NaturalLess("10.2.1", "10.2.1.1"))
	require.False(t, NaturalLess("12.3.4", "2.2.1"))
}

// TestEveryMatrixHasAnUpstream: a matrix nobody re-reads silently drifts.
func TestEveryMatrixHasAnUpstream(t *testing.T) {
	bs, err := benchmarks.Load()
	require.NoError(t, err)
	for _, b := range bs {
		_, ok := SourceFor(b.ID)
		require.True(t, ok, "%s declares no upstream in upstream.Sources", b.ID)
	}
}
