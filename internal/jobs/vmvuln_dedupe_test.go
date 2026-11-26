package jobs

import (
	"context"
	"testing"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// edgeLineage serves enrich's lineage reads from the fake inventory's edges.
type edgeLineage struct{ edges []asset.Edge }

func (l edgeLineage) EdgesInto(_ context.Context, dstID, edgeType string) ([]asset.Edge, error) {
	var out []asset.Edge
	for _, e := range l.edges {
		if e.DstID == dstID && e.EdgeType == edgeType {
			out = append(out, e)
		}
	}
	return out, nil
}

func (l edgeLineage) EdgesOutBatch(_ context.Context, ids []string, edgeType string) ([]asset.Edge, error) {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []asset.Edge
	for _, e := range l.edges {
		if want[e.SrcID] && e.EdgeType == edgeType {
			out = append(out, e)
		}
	}
	return out, nil
}

func (l edgeLineage) LineageSources(ctx context.Context, ids []string, typ string, limit int) ([]asset.Edge, bool, error) {
	var out []asset.Edge
	for _, id := range ids {
		edges, err := l.EdgesInto(ctx, id, typ)
		if err != nil {
			return nil, false, err
		}
		out = append(out, edges...)
	}
	return out[:min(len(out), limit)], len(out) > limit, nil
}
func (l edgeLineage) LineageTargets(ctx context.Context, ids []string, typ string, limit int) ([]asset.Edge, bool, error) {
	out, err := l.EdgesOutBatch(ctx, ids, typ)
	return out[:min(len(out), limit)], len(out) > limit, err
}
func (l edgeLineage) AnyConfirmedExposure(ctx context.Context, ids []string) (bool, error) {
	out, err := l.EdgesOutBatch(ctx, ids, "exposed_to_internet")
	return len(out) > 0, err
}

// recordedFleets lists the fleet findings a pass recorded, as finding.Service
// would after RecordObserved.
type recordedFleets struct{ fs *fakeVMVulnFindings }

func (r recordedFleets) List(_ context.Context, flt finding.Filter) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, f := range r.fs.recorded {
		if f.Source == flt.Source && f.CheckID == flt.CheckID {
			out = append(out, f)
		}
	}
	return out, nil
}

// The contract between the fleet job and the package finding's enrichment: one
// vulnerable package run only by inventoried VMs is reported once per fleet.
// The fleet findings this job records cover every VM runner, so the package
// finding defers to them (routine, no score) while must-fix is decided on the
// exposed host's fleet finding. A VM running the package that the job could not
// group — its inventory went unknown while its edge is still fresh — breaks the
// coverage, and the package finding keeps its own evaluation rather than drop
// that host.
func TestVMVuln_FleetFindingsAreCanonicalForVMOnlyPackages(t *testing.T) {
	inv := &fakeVMInventory{
		byType: map[string][]asset.Asset{"ec2_instance": {
			ec2("i-a", "web-asg", "ami-1", asset.PackageInventorySSM),
			ec2("i-b", "web-asg", "ami-1", asset.PackageInventorySSM),
			ec2("i-solo", "", "ami-2", asset.PackageInventorySSM),
		}},
		edges: []asset.Edge{
			runsPkg("i-a"), runsPkg("i-b"), runsPkg("i-solo"),
			{SrcID: "i-b", SrcType: "ec2_instance", DstID: "internet", EdgeType: "exposed_to_internet"},
		},
	}
	pkg := pkgCVE()
	fs := &fakeVMVulnFindings{byResource: map[string][]finding.Finding{testPurl: {pkg}}}
	w := &VMVulnWorker{assets: inv, findings: fs}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	require.Len(t, fs.recorded, 2)

	sc := enrich.SupplyChainExposure{Graph: edgeLineage{inv.edges}, Fleets: recordedFleets{fs}}
	canonical, instances, err := sc.FleetCanonical(context.Background(), pkg)
	require.NoError(t, err)
	require.True(t, canonical, "every VM runner is carried by a fleet finding")
	require.Equal(t, 3, instances)

	// i-c runs the package (fresh edge) but its inventory is no longer known, so
	// the fleet job makes no claim about it.
	inv.byType["ec2_instance"] = append(inv.byType["ec2_instance"], ec2("i-c", "", "ami-3", asset.PackageInventoryNone))
	inv.edges = append(inv.edges, runsPkg("i-c"))
	fs.recorded = nil
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	sc = enrich.SupplyChainExposure{Graph: edgeLineage{inv.edges}, Fleets: recordedFleets{fs}}
	canonical, _, err = sc.FleetCanonical(context.Background(), pkg)
	require.NoError(t, err)
	require.False(t, canonical, "an ungrouped VM runner keeps the package finding's own evaluation")
}

func TestGroupedPackageFindings_OncePerPackageFinding(t *testing.T) {
	a := finding.Finding{ID: "pkg-a"}
	b := finding.Finding{ID: "pkg-b"}
	groups := map[string]*fleetGroup{
		"1": {pkg: b}, "2": {pkg: a}, "3": {pkg: b},
	}
	got := groupedPackageFindings(groups)
	require.Equal(t, []string{"pkg-a", "pkg-b"}, []string{got[0].ID, got[1].ID})
	require.Len(t, got, 2)
}
