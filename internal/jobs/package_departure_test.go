package jobs

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/obs"
)

// fakeDepartures serves departure evidence from memory: it is the asset
// store, the deletion records and the finding reader at once.
type fakeDepartures struct {
	runners  []asset.PackageRunner
	assets   map[string]asset.Asset
	deleted  map[string]time.Time
	edges    map[string][]asset.Edge // fresh outgoing edges by src id
	findings []finding.Finding
	// failFor fails a PackageRunners call naming this package (the oversized
	// one), batched or alone.
	failFor string
	err     error
	counts  map[string]int // the last ObservePackageDepartures
	// largestRunnerRead and listCalls record call shapes.
	largestRunnerRead, listCalls int
}

func (f *fakeDepartures) readers() departureReaders {
	return departureReaders{assets: f, deletions: f, findings: f, metrics: f}
}

func (f *fakeDepartures) PackageRunners(_ context.Context, ids []string) ([]asset.PackageRunner, error) {
	f.largestRunnerRead = max(f.largestRunnerRead, len(ids))
	if f.err != nil {
		return nil, f.err
	}
	want := map[string]bool{}
	for _, id := range ids {
		if id == f.failFor {
			return nil, errors.New("code: 62, Max query size exceeded")
		}
		want[id] = true
	}
	var out []asset.PackageRunner
	for _, r := range f.runners {
		if want[r.PackageID] {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeDepartures) ByIDs(_ context.Context, ids []string) ([]asset.Asset, error) {
	var out []asset.Asset
	for _, id := range ids {
		if a, ok := f.assets[id]; ok {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeDepartures) AssetDeletions(_ context.Context, ids []string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	for _, id := range ids {
		if at, ok := f.deleted[id]; ok {
			out[id] = at
		}
	}
	return out, nil
}

func (f *fakeDepartures) ByResourceIDs(_ context.Context, ids []string) ([]finding.Finding, error) {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []finding.Finding
	for _, x := range f.findings {
		if want[x.ResourceID] {
			out = append(out, x)
		}
	}
	return out, nil
}

func (f *fakeDepartures) ListByType(_ context.Context, typ string, _ int) ([]asset.Asset, error) {
	f.listCalls++
	var out []asset.Asset
	for _, a := range f.assets {
		if a.Type == typ {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeDepartures) EdgesOutBatch(_ context.Context, ids []string, edgeType string) ([]asset.Edge, error) {
	var out []asset.Edge
	for _, id := range ids {
		for _, e := range f.edges[id] {
			if e.EdgeType == edgeType {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (f *fakeDepartures) ObservePackageDepartures(_ string, counts map[string]int) { f.counts = counts }

var (
	depNow   = time.Now()
	lapsedAt = depNow.Add(-72 * time.Hour) // past the 48h freshness window
)

// supersededBy: runner's producer read it an hour ago, without pkg.
func supersededBy(pkg, runner string) asset.PackageRunner {
	return asset.PackageRunner{PackageID: pkg, RunnerID: runner, RunnerType: "ec2_instance", EdgeType: "runs_package",
		EdgeAt: lapsedAt, InventoryAt: depNow.Add(-time.Hour)}
}

// unobserved: runner's producer has not stamped anything since the edge.
func unobserved(pkg, runner string) asset.PackageRunner {
	return asset.PackageRunner{PackageID: pkg, RunnerID: runner, RunnerType: "ec2_instance", EdgeType: "runs_package",
		EdgeAt: lapsedAt, InventoryAt: lapsedAt}
}

func vm(id, asg string, lastSeen time.Time) asset.Asset {
	a := asset.Asset{ID: id, Type: "ec2_instance", Provider: asset.ProviderAWS, AccountID: "111", Region: "eu-west-1",
		LastSeen: lastSeen, Tags: map[string]string{}, Metadata: map[string]string{}}
	if asg != "" {
		a.Tags["aws:autoscaling:groupName"] = asg
	}
	return a
}

func runsPackage(src, purl string) asset.Edge {
	return asset.Edge{SrcID: src, SrcType: "ec2_instance", DstID: purl, DstType: "package", EdgeType: "runs_package"}
}

// goneEvidence proves each purl departed (its only runner was re-read without
// it) with no upgrade in sight: resource_gone.
func goneEvidence(purls ...string) *fakeDepartures {
	d := &fakeDepartures{assets: map[string]asset.Asset{}}
	for _, p := range purls {
		runner := "runner-of-" + p
		d.runners = append(d.runners, supersededBy(p, runner))
		d.assets[runner] = vm(runner, "", depNow)
	}
	return d
}

func TestPurlParts(t *testing.T) {
	for _, tc := range []struct{ purl, key, version string }{
		{"pkg:npm/lodash@4.17.20", "pkg:npm/lodash", "4.17.20"},
		{"pkg:rpm/amzn/openssl@1:1.0.2k-24.amzn2?arch=x86_64", "pkg:rpm/amzn/openssl?arch=x86_64", "1:1.0.2k-24.amzn2"},
		{"pkg:npm/%40scope/name@1.0.0", "pkg:npm/%40scope/name", "1.0.0"},
		{"pkg:generic/noversion", "pkg:generic/noversion", ""},
	} {
		key, version := purlParts(tc.purl)
		require.Equal(t, tc.key, key, tc.purl)
		require.Equal(t, tc.version, version, tc.purl)
	}
}

// "fixed" means NEWER under the ecosystem's comparator; an ecosystem without
// one never claims an upgrade.
func TestVersionNewer(t *testing.T) {
	for _, tc := range []struct {
		typ, prev, next string
		newer, ok       bool
	}{
		{"rpm", "1:1.0.2k-24.amzn2", "1:1.0.2k-25.amzn2", true, true},
		{"rpm", "1:1.0.2k-25.amzn2", "1:1.0.2k-24.amzn2", false, true},
		{"deb", "3.0.11-1~deb12u1", "3.0.11-1~deb12u2", true, true},
		{"deb", "3.0.11-1", "3.0.11-1~deb12u2", false, true}, // a tilde build is OLDER
		{"npm", "4.17.20", "4.17.21", true, true},
		{"npm", "4.17.21", "4.17.20", false, true},
		{"golang", "v0.9.0", "v0.10.0", true, true},
		{"cargo", "not-semver", "1.0.0", false, false},
		{"apk", "3.1.4-r5", "3.1.4-r6", false, false},
		{"pypi", "2.19.0", "2.31.0", false, false},
	} {
		newer, ok := versionNewer(tc.typ, tc.prev, tc.next)
		require.Equal(t, tc.ok, ok, "%s %s→%s comparable", tc.typ, tc.prev, tc.next)
		require.Equal(t, tc.newer, newer, "%s %s→%s newer", tc.typ, tc.prev, tc.next)
	}
}

// The core table: a lapsed edge alone never proves a departure.
func TestJudgeDepartures(t *testing.T) {
	const old, newer, older = "pkg:rpm/amzn/openssl@1.0.1?arch=x86_64", "pkg:rpm/amzn/openssl@1.0.2?arch=x86_64", "pkg:rpm/amzn/openssl@1.0.0?arch=x86_64"
	seenNow := depNow.Add(-10 * time.Minute)
	for _, tc := range []struct {
		name string
		dep  *fakeDepartures
		want string
	}{
		{
			name: "producer outage: runner unobserved and still collected — withheld",
			dep: &fakeDepartures{runners: []asset.PackageRunner{unobserved(old, "i-1")},
				assets: map[string]asset.Asset{"i-1": vm("i-1", "", seenNow)}},
			want: obs.DepartureWithheld,
		},
		{
			name: "connector outage: runner stopped being collected, no deletion recorded — withheld",
			dep: &fakeDepartures{runners: []asset.PackageRunner{unobserved(old, "i-1")},
				assets: map[string]asset.Asset{"i-1": vm("i-1", "", lapsedAt)}},
			want: obs.DepartureWithheld,
		},
		{
			name: "deletion recorded BEFORE the runner was seen again — it came back, withheld",
			dep: &fakeDepartures{runners: []asset.PackageRunner{unobserved(old, "i-1")},
				assets:  map[string]asset.Asset{"i-1": vm("i-1", "", seenNow)},
				deleted: map[string]time.Time{"i-1": lapsedAt}},
			want: obs.DepartureWithheld,
		},
		{
			name: "no runner row — withheld",
			dep:  &fakeDepartures{runners: []asset.PackageRunner{unobserved(old, "i-1")}},
			want: obs.DepartureWithheld,
		},
		{
			name: "no runner evidence at all — left to the age fallback",
			dep:  &fakeDepartures{},
			want: "",
		},
		{
			name: "re-read without the package, nothing replaces it — resource_gone",
			dep: &fakeDepartures{runners: []asset.PackageRunner{supersededBy(old, "i-1")},
				assets: map[string]asset.Asset{"i-1": vm("i-1", "", seenNow)}},
			want: obs.DepartureGone,
		},
		{
			name: "re-read with the package at a NEWER version — fixed",
			dep: &fakeDepartures{runners: []asset.PackageRunner{supersededBy(old, "i-1")},
				assets: map[string]asset.Asset{"i-1": vm("i-1", "", seenNow)},
				edges:  map[string][]asset.Edge{"i-1": {runsPackage("i-1", newer)}}},
			want: obs.DepartureFixed,
		},
		{
			name: "re-read with the package at an OLDER version — a downgrade is not a fix",
			dep: &fakeDepartures{runners: []asset.PackageRunner{supersededBy(old, "i-1")},
				assets: map[string]asset.Asset{"i-1": vm("i-1", "", seenNow)},
				edges:  map[string][]asset.Edge{"i-1": {runsPackage("i-1", older)}}},
			want: obs.DepartureGone,
		},
		{
			name: "sync recorded the runner deleted after its last sighting — resource_gone",
			dep: &fakeDepartures{runners: []asset.PackageRunner{unobserved(old, "i-1")},
				assets:  map[string]asset.Asset{"i-1": vm("i-1", "", lapsedAt)},
				deleted: map[string]time.Time{"i-1": lapsedAt.Add(2 * time.Hour)}},
			want: obs.DepartureGone,
		},
		{
			name: "runner unseen past the absence fallback — presumed gone",
			dep: &fakeDepartures{runners: []asset.PackageRunner{unobserved(old, "i-1")},
				assets: map[string]asset.Asset{"i-1": vm("i-1", "", depNow.Add(-absenceFallback-time.Hour))}},
			want: obs.DepartureGone,
		},
		{
			name: "ASG rolled onto a rebuilt AMI: the old member deleted, its replacement runs the newer version — fixed",
			dep: &fakeDepartures{runners: []asset.PackageRunner{unobserved(old, "i-old")},
				assets:  map[string]asset.Asset{"i-old": vm("i-old", "web", lapsedAt), "i-new": vm("i-new", "web", seenNow)},
				deleted: map[string]time.Time{"i-old": lapsedAt.Add(time.Hour)},
				edges:   map[string][]asset.Edge{"i-new": {runsPackage("i-new", newer)}}},
			want: obs.DepartureFixed,
		},
		{
			name: "one runner accounted for, one in outage — withheld",
			dep: &fakeDepartures{runners: []asset.PackageRunner{supersededBy(old, "i-1"), unobserved(old, "i-2")},
				assets: map[string]asset.Asset{"i-1": vm("i-1", "", seenNow), "i-2": vm("i-2", "", seenNow)}},
			want: obs.DepartureWithheld,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := judgeDepartures(context.Background(), tc.dep.readers(), []string{old}, depNow)
			require.Equal(t, tc.want, got[old].outcome)
		})
	}
}

// The 6h margin is the line between "a later read" and the skew inside one
// write: a runner whose newest stamp is only minutes after the lapsed edge was
// written in the same pass, and proves nothing.
func TestJudgeDepartures_SupersessionMarginBoundary(t *testing.T) {
	const pkg = "pkg:npm/a@1.0.0"
	for _, tc := range []struct {
		gap  time.Duration
		want string
	}{
		{departureMargin - time.Minute, obs.DepartureWithheld},
		{departureMargin, obs.DepartureWithheld},
		{departureMargin + time.Minute, obs.DepartureGone},
	} {
		r := asset.PackageRunner{PackageID: pkg, RunnerID: "repo", RunnerType: "github_repo", EdgeType: "depends_on",
			EdgeAt: lapsedAt, InventoryAt: lapsedAt.Add(tc.gap)}
		dep := &fakeDepartures{runners: []asset.PackageRunner{r},
			assets: map[string]asset.Asset{"repo": {ID: "repo", Type: "github_repo", LastSeen: depNow}}}
		got := judgeDepartures(context.Background(), dep.readers(), []string{pkg}, depNow)
		require.Equal(t, tc.want, got[pkg].outcome, "gap %s", tc.gap)
	}
}

// The absence fallback is bounded on both sides of its line.
func TestAssetGone_FallbackBoundary(t *testing.T) {
	require.False(t, assetGone(vm("i", "", depNow.Add(-absenceFallback+time.Minute)), time.Time{}, depNow))
	require.True(t, assetGone(vm("i", "", depNow.Add(-absenceFallback-time.Minute)), time.Time{}, depNow))
	require.False(t, assetGone(asset.Asset{}, depNow, depNow), "no sighting at all proves nothing")
}

// One package whose runners cannot be read (too many for one query, a
// timeout) withholds only itself; every other departure is still judged.
func TestJudgeDepartures_ReadErrorWithholdsOnlyThatPackage(t *testing.T) {
	const bad, good = "pkg:deb/debian/openssl@3.0.11-1", "pkg:npm/a@1.0.0"
	dep := goneEvidence(good)
	dep.runners = append(dep.runners, supersededBy(bad, "img"))
	dep.assets["img"] = vm("img", "", depNow)
	dep.failFor = bad
	got := judgeDepartures(context.Background(), dep.readers(), []string{bad, good}, depNow)
	require.Equal(t, obs.DepartureWithheldReadErr, got[bad].outcome)
	require.Equal(t, obs.DepartureGone, got[good].outcome, "the healthy package is judged regardless")
}

func TestJudgeDepartures_UnwiredReadersProveNothing(t *testing.T) {
	got := judgeDepartures(context.Background(), departureReaders{}, []string{"pkg:npm/a@1"}, depNow)
	require.Equal(t, obs.DepartureWithheldReadErr, got["pkg:npm/a@1"].outcome)
}

// A finding on a package with no runner evidence left (its edges aged out of
// the TTL) resolves once last observed before the fallback — never held open
// forever — and stays open while it is younger.
func TestResolveDepartures_AgedOutFallback(t *testing.T) {
	dep := &fakeDepartures{}
	young := finding.Finding{ID: "young", ResourceType: "package", ResourceID: "pkg:npm/y@1", CheckID: "CVE-1",
		LastObservedAt: depNow.Add(-absenceFallback + time.Hour)}
	old := finding.Finding{ID: "old", ResourceType: "package", ResourceID: "pkg:npm/o@1", CheckID: "CVE-1",
		LastObservedAt: depNow.Add(-absenceFallback - time.Hour)}
	fixed, gone := resolveDepartures(context.Background(), dep.readers(), "test", []finding.Finding{young, old}, readAll, depNow)
	require.Empty(t, fixed)
	require.Equal(t, []finding.Finding{old}, gone)
	require.Equal(t, 1, dep.counts[obs.DepartureAgedOut])
	require.Equal(t, 1, dep.counts[obs.DepartureWithheld], "the withheld count is published")
}

// An upgrade whose newer purl still carries an open finding for the same check
// did not fix it: the old purl departed, resource_gone.
func TestResolveDepartures_UpgradeStillVulnerableIsNotFixed(t *testing.T) {
	const old, newer = "pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.21"
	dep := &fakeDepartures{runners: []asset.PackageRunner{supersededBy(old, "repo")},
		assets: map[string]asset.Asset{"repo": vm("repo", "", depNow)},
		edges:  map[string][]asset.Edge{"repo": {runsPackage("repo", newer)}},
		findings: []finding.Finding{
			{ID: "n1", ResourceType: "package", ResourceID: newer, CheckID: "CVE-STILL"},
		}}
	still := finding.Finding{ID: "f1", ResourceType: "package", ResourceID: old, CheckID: "CVE-STILL", LastObservedAt: lapsedAt}
	cured := finding.Finding{ID: "f2", ResourceType: "package", ResourceID: old, CheckID: "CVE-CURED", LastObservedAt: lapsedAt}
	fixed, gone := resolveDepartures(context.Background(), dep.readers(), "test", []finding.Finding{still, cured}, readAll, depNow)
	require.Equal(t, []finding.Finding{cured}, fixed)
	require.Equal(t, []finding.Finding{still}, gone)
}

// A fleet-wide AMI roll departs thousands of packages at once. They are judged
// a batch at a time (bounded runner evidence in memory), and the fleet listing
// a lineage check needs is read once for the whole judgement, not per batch.
func TestJudgeDepartures_BatchesAndListsLineageOnce(t *testing.T) {
	dep := &fakeDepartures{assets: map[string]asset.Asset{
		"i-old": vm("i-old", "web", lapsedAt), "i-new": vm("i-new", "web", depNow),
	}, deleted: map[string]time.Time{"i-old": lapsedAt.Add(time.Hour)}}
	var purls []string
	for i := range departureBatch*2 + 7 {
		p := fmt.Sprintf("pkg:rpm/amzn/lib%04d@1.0-1", i)
		purls = append(purls, p)
		dep.runners = append(dep.runners, unobserved(p, "i-old"))
	}
	got := judgeDepartures(context.Background(), dep.readers(), purls, depNow)
	require.Len(t, got, len(purls))
	for _, p := range purls {
		require.Equal(t, obs.DepartureGone, got[p].outcome)
	}
	require.LessOrEqual(t, dep.largestRunnerRead, departureBatch)
	require.Equal(t, 1, dep.listCalls, "the fleet listing is shared across batches")
}

// readAll vouches that every upgrade target's advisories were read in full.
func readAll(string) bool { return true }

// An upgrade target whose advisories were not read in full this run (its
// query was incomplete, it was asked by binary name, or nothing here can query
// it) has no open finding because nobody looked, not because it is cured: the
// finding is withheld until the target is read — neither fixed nor gone.
func TestResolveDepartures_UnreadTargetWithholdsFixed(t *testing.T) {
	const old, newer = "pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.21"
	dep := &fakeDepartures{runners: []asset.PackageRunner{supersededBy(old, "repo")},
		assets: map[string]asset.Asset{"repo": vm("repo", "", depNow)},
		edges:  map[string][]asset.Edge{"repo": {runsPackage("repo", newer)}}}
	f := finding.Finding{ID: "f", ResourceType: "package", ResourceID: old, CheckID: "CVE-1", LastObservedAt: lapsedAt}
	unread := func(p string) bool { return p != newer }
	fixed, gone := resolveDepartures(context.Background(), dep.readers(), "test", []finding.Finding{f}, unread, depNow)
	require.Empty(t, fixed)
	require.Empty(t, gone)
	require.Equal(t, 1, dep.counts[obs.DepartureWithheld])
}
