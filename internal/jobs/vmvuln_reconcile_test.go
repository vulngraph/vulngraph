package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

const upgradedPurl = "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.12"

func openFleet(id, kind, fleetID string) finding.Finding {
	return finding.Finding{ID: id, Source: vmVulnSource, CheckID: "CVE-2023-0286", Metadata: map[string]string{
		"fleet_kind": kind, "fleet_id": fleetID, "purl": testPurl, "package_finding_id": "pkgfinding",
	}}
}

func stale(a asset.Asset) asset.Asset {
	a.LastSeen = time.Now().Add(-5 * 24 * time.Hour)
	return a
}

// The reconcile acts on evidence only: a fleet whose every member the sync
// recorded deleted is gone, a re-inventoried fleet running a newer version is fixed, one
// that dropped the package is resource_gone, and a fleet with a dark member or
// one that simply stopped being collected keeps its finding.
func TestVMVuln_ReconcileOnEvidence(t *testing.T) {
	inv := &fakeVMInventory{byType: map[string][]asset.Asset{"ec2_instance": {
		ec2("i-upgraded", "", "ami-1", asset.PackageInventorySSM),
		ec2("i-removed", "", "ami-3", asset.PackageInventorySSM),
		ec2("i-known", "", "ami-2", asset.PackageInventorySSM),
		ec2("i-dark", "", "ami-2", asset.PackageInventoryNone),
		stale(ec2("i-terminated", "", "ami-9", asset.PackageInventorySSM)),
	}}, edges: []asset.Edge{
		{SrcID: "i-upgraded", SrcType: "ec2_instance", DstID: upgradedPurl, DstType: "package", EdgeType: "runs_package"},
	}}
	fs := &fakeVMVulnFindings{open: []finding.Finding{
		openFleet("f-upgraded", "ami", "111122223333/ami-1"),
		openFleet("f-removed", "ami", "111122223333/ami-3"),
		openFleet("f-dark", "ami", "111122223333/ami-2"),
		openFleet("f-gone", "ami", "111122223333/ami-9"),
	}}
	deleted := &fakeDepartures{deleted: map[string]time.Time{"i-terminated": time.Now().Add(-4 * 24 * time.Hour)}}
	require.NoError(t, (&VMVulnWorker{assets: inv, findings: fs, deletions: deleted}).Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	require.Equal(t, []string{"f-upgraded"}, fs.resolved[finding.ReasonFixed], "an upgrade on the fleet is the fix")
	require.ElementsMatch(t, []string{"f-removed", "f-gone"}, fs.resolved[finding.ReasonResourceGone])

	// A truncated VM listing resolves nothing.
	many := make([]asset.Asset, listVMLimit)
	for i := range many {
		many[i] = ec2("i-x", "", "ami-1", asset.PackageInventorySSM)
	}
	inv.byType["ec2_instance"] = many
	fs.resolved = nil
	require.NoError(t, (&VMVulnWorker{assets: inv, findings: fs}).Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	require.Empty(t, fs.resolved)
}

// An upgrade only fixes what it fixes: a newer version still carrying the same
// CVE is a departure from the old purl, and a downgrade is never a fix.
func TestVMVuln_UpgradeMustBeNewerAndCured(t *testing.T) {
	const downgraded = "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.8"
	for _, tc := range []struct {
		name       string
		runs       string
		vulnerable bool
		want       finding.ResolutionReason
	}{
		{"newer and cured", upgradedPurl, false, finding.ReasonFixed},
		{"newer but still vulnerable", upgradedPurl, true, finding.ReasonResourceGone},
		{"downgraded", downgraded, false, finding.ReasonResourceGone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := &fakeVMInventory{
				byType: map[string][]asset.Asset{"ec2_instance": {ec2("i-a", "", "ami-1", asset.PackageInventorySSM)}},
				edges:  []asset.Edge{{SrcID: "i-a", SrcType: "ec2_instance", DstID: tc.runs, DstType: "package", EdgeType: "runs_package"}},
			}
			fs := &fakeVMVulnFindings{byResource: map[string][]finding.Finding{},
				open: []finding.Finding{openFleet("f", "ami", "111122223333/ami-1")}}
			if tc.vulnerable {
				still := pkgCVE()
				still.ID, still.ResourceID = "pkg-new", tc.runs
				fs.byResource[tc.runs] = []finding.Finding{still}
			}
			require.NoError(t, (&VMVulnWorker{assets: inv, findings: fs}).Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
			require.Equal(t, []string{"f"}, fs.resolved[tc.want])
		})
	}
}

// A fleet key no listed VM maps to any more (a member's ASG tag appeared, or
// every member aged out of the listing) has nothing left to judge it: its
// finding resolves once older than the absence fallback, never held forever.
func TestVMVuln_UnlistedFleetAgesOut(t *testing.T) {
	inv := &fakeVMInventory{byType: map[string][]asset.Asset{"ec2_instance": {
		ec2("i-a", "web", "ami-1", asset.PackageInventorySSM), // now keyed by its ASG, not the AMI
	}}}
	young := openFleet("f-young", "ami", "111122223333/ami-1")
	young.LastObservedAt = time.Now().Add(-absenceFallback + time.Hour)
	old := openFleet("f-old", "ami", "111122223333/ami-2")
	old.LastObservedAt = time.Now().Add(-absenceFallback - time.Hour)
	fs := &fakeVMVulnFindings{open: []finding.Finding{young, old}}
	require.NoError(t, (&VMVulnWorker{assets: inv, findings: fs}).Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	require.Equal(t, map[finding.ResolutionReason][]string{finding.ReasonResourceGone: {"f-old"}}, fs.resolved)
}

// An expired connector credential stops collection of the whole account: every
// VM's last_seen lapses together. That is not a fleet terminating.
func TestVMVuln_CollectionOutageResolvesNothing(t *testing.T) {
	inv := &fakeVMInventory{byType: map[string][]asset.Asset{"ec2_instance": {
		stale(ec2("i-a", "web", "ami-1", asset.PackageInventorySSM)),
		stale(ec2("i-b", "web", "ami-1", asset.PackageInventorySSM)),
	}}}
	fs := &fakeVMVulnFindings{open: []finding.Finding{openFleet("f-web", "asg", "111122223333/eu-west-1/web")}}
	require.NoError(t, (&VMVulnWorker{assets: inv, findings: fs}).Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	require.Empty(t, fs.resolved, "a whole scope going quiet proves no member deleted")

	// A PARTIAL sweep (one zone failing, a paging error) keeps stamping the
	// siblings it did return; the members it missed have no recorded deletion
	// — the sync deletes only on a complete, covered enumeration — so the fleet
	// stays open.
	inv.byType["ec2_instance"] = []asset.Asset{
		stale(ec2("i-a", "web", "ami-1", asset.PackageInventorySSM)),
		ec2("i-other", "", "ami-7", asset.PackageInventorySSM),
	}
	require.NoError(t, (&VMVulnWorker{assets: inv, findings: fs, deletions: &fakeDepartures{}}).Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	require.Empty(t, fs.resolved, "a fresh sibling is no proof a missing member was deleted")

	// Bounded: a member unseen past the absence fallback is presumed gone.
	long := ec2("i-a", "web", "ami-1", asset.PackageInventorySSM)
	long.LastSeen = time.Now().Add(-absenceFallback - time.Hour)
	inv.byType["ec2_instance"] = []asset.Asset{long}
	require.NoError(t, (&VMVulnWorker{assets: inv, findings: fs}).Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	require.Equal(t, []string{"f-web"}, fs.resolved[finding.ReasonResourceGone])
}

// A fleet still running the purl lost its fleet finding because the package
// finding closed: it inherits that reason — but never resource_gone, which a
// fleet running the package contradicts.
func TestVMVuln_StillRunningInheritsPackageReason(t *testing.T) {
	for _, tc := range []struct {
		pkgReason finding.ResolutionReason
		want      finding.ResolutionReason // "" = withheld
	}{
		{finding.ReasonFixed, finding.ReasonFixed},
		{finding.ReasonManual, finding.ReasonManual},
		{finding.ReasonResourceGone, ""},
	} {
		t.Run(string(tc.pkgReason), func(t *testing.T) {
			pkg := pkgCVE()
			pkg.ResolvedAt, pkg.ResolutionReason = time.Now(), tc.pkgReason
			inv := &fakeVMInventory{
				byType: map[string][]asset.Asset{"ec2_instance": {ec2("i-a", "", "ami-1", asset.PackageInventorySSM)}},
				edges:  []asset.Edge{runsPkg("i-a")},
			}
			fs := &fakeVMVulnFindings{
				byResource: map[string][]finding.Finding{testPurl: {pkg}},
				open:       []finding.Finding{openFleet("f", "ami", "111122223333/ami-1")},
			}
			require.NoError(t, (&VMVulnWorker{assets: inv, findings: fs}).Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
			if tc.want == "" {
				require.Empty(t, fs.resolved)
				return
			}
			require.Equal(t, map[finding.ResolutionReason][]string{tc.want: {"f"}}, fs.resolved)
		})
	}
}

// The finding stays on the member it already sits on while that member stays
// eligible — no resource churn pass to pass — but moves to an exposed member
// when one appears, so must-fix still sees the exposure.
func TestVMVuln_RepresentativeIsSticky(t *testing.T) {
	inv := &fakeVMInventory{
		byType: map[string][]asset.Asset{"ec2_instance": {
			ec2("i-a", "web", "ami-1", asset.PackageInventorySSM),
			ec2("i-b", "web", "ami-1", asset.PackageInventorySSM),
			ec2("i-c", "web", "ami-1", asset.PackageInventorySSM),
		}},
		edges: []asset.Edge{runsPkg("i-a"), runsPkg("i-b"), runsPkg("i-c")},
	}
	fs := &fakeVMVulnFindings{byResource: map[string][]finding.Finding{testPurl: {pkgCVE()}}}
	w := &VMVulnWorker{assets: inv, findings: fs}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	require.Len(t, fs.recorded, 1)
	first := fs.recorded[0]
	require.Equal(t, "i-a", first.ResourceID)

	first.ResourceID = "i-c"
	fs.open, fs.recorded = []finding.Finding{first}, nil
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	require.Equal(t, "i-c", fs.recorded[0].ResourceID, "the previous member is kept while eligible")

	inv.edges = append(inv.edges, asset.Edge{SrcID: "i-b", SrcType: "ec2_instance", DstID: "internet", EdgeType: "exposed_to_internet"})
	fs.recorded = nil
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	require.Equal(t, "i-b", fs.recorded[0].ResourceID, "an exposed member takes precedence")
	require.Equal(t, "i-b", fs.recorded[0].Metadata["exposed_instance_ids"])
}
