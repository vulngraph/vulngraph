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

type fakeVMInventory struct {
	byType map[string][]asset.Asset
	edges  []asset.Edge
}

func (f *fakeVMInventory) ListByType(_ context.Context, typ string, _ int) ([]asset.Asset, error) {
	return f.byType[typ], nil
}

func (f *fakeVMInventory) EdgesOutBatch(_ context.Context, srcIDs []string, edgeType string) ([]asset.Edge, error) {
	want := map[string]bool{}
	for _, id := range srcIDs {
		want[id] = true
	}
	var out []asset.Edge
	for _, e := range f.edges {
		if want[e.SrcID] && e.EdgeType == edgeType {
			out = append(out, e)
		}
	}
	return out, nil
}

type fakeVMVulnFindings struct {
	byResource map[string][]finding.Finding
	open       []finding.Finding
	recorded   []finding.Finding
	resolved   map[finding.ResolutionReason][]string
}

func (f *fakeVMVulnFindings) ByResourceIDs(_ context.Context, ids []string) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, id := range ids {
		out = append(out, f.byResource[id]...)
	}
	return out, nil
}

func (f *fakeVMVulnFindings) List(_ context.Context, flt finding.Filter) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, o := range f.open {
		if o.Source == flt.Source {
			out = append(out, o)
		}
	}
	return out, nil
}

func (f *fakeVMVulnFindings) RecordObserved(_ context.Context, fs []finding.Finding) error {
	f.recorded = append(f.recorded, fs...)
	return nil
}

func (f *fakeVMVulnFindings) Resolve(_ context.Context, fs []finding.Finding, reason finding.ResolutionReason) error {
	if f.resolved == nil {
		f.resolved = map[finding.ResolutionReason][]string{}
	}
	for _, x := range fs {
		f.resolved[reason] = append(f.resolved[reason], x.ID)
	}
	return nil
}

const testPurl = "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10"

func ec2(id, asg, ami, inventory string) asset.Asset {
	a := asset.Asset{
		ID: id, Name: id, Type: "ec2_instance", Region: "eu-west-1", AccountID: "111122223333",
		LastSeen: time.Now(), Tags: map[string]string{},
		Metadata: map[string]string{"image_id": ami, asset.MetaPackageInventory: inventory},
	}
	if asg != "" {
		a.Tags["aws:autoscaling:groupName"] = asg
	}
	if inventory == asset.PackageInventorySSM {
		a.Metadata[asset.MetaPackageCVEMatchable] = "true"
		a.Metadata[asset.MetaPackageEcosystem] = "Ubuntu:22.04:LTS"
	}
	return a
}

func runsPkg(id string) asset.Edge {
	return asset.Edge{SrcID: id, SrcType: "ec2_instance", DstID: testPurl, DstType: "package", EdgeType: "runs_package"}
}

func pkgCVE() finding.Finding {
	return finding.Finding{
		ID: "pkgfinding", Source: "supply_chain", Type: "vulnerable_dependency", Severity: finding.SeverityHigh,
		ResourceType: "package", ResourceID: testPurl, ResourceName: "openssl", CheckID: "CVE-2023-0286",
		Title: "X.400 address type confusion", Remediation: "Upgrade openssl to 3.0.2-0ubuntu1.12 or later.",
	}
}

// A 3-instance ASG on one vulnerable package is ONE finding carrying the fleet's
// instance count, sitting on its exposed member; a standalone instance from an
// AMI is its own fleet.
func TestVMVuln_GroupsPerFleet(t *testing.T) {
	inv := &fakeVMInventory{
		byType: map[string][]asset.Asset{"ec2_instance": {
			ec2("i-a", "web-asg", "ami-1", asset.PackageInventorySSM),
			ec2("i-b", "web-asg", "ami-1", asset.PackageInventorySSM),
			ec2("i-c", "web-asg", "ami-1", asset.PackageInventorySSM),
			ec2("i-solo", "", "ami-2", asset.PackageInventorySSM),
		}},
		edges: []asset.Edge{
			runsPkg("i-a"), runsPkg("i-b"), runsPkg("i-c"), runsPkg("i-solo"),
			{SrcID: "i-b", SrcType: "ec2_instance", DstID: "internet", EdgeType: "exposed_to_internet"},
		},
	}
	fs := &fakeVMVulnFindings{byResource: map[string][]finding.Finding{testPurl: {pkgCVE()}}}
	w := &VMVulnWorker{assets: inv, findings: fs}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))

	require.Len(t, fs.recorded, 2, "one finding per fleet, not per instance")
	byFleet := map[string]finding.Finding{}
	for _, f := range fs.recorded {
		byFleet[f.Metadata["fleet_kind"]] = f
	}
	asg := byFleet["asg"]
	require.Equal(t, "3", asg.Metadata["affected_instances"])
	require.Equal(t, "i-a,i-b,i-c", asg.Metadata["affected_instance_ids"])
	require.Equal(t, "1", asg.Metadata["exposed_instances"])
	require.Equal(t, "i-b", asg.ResourceID, "the finding sits on an exposed member so must-fix sees the exposure")
	require.Equal(t, "ec2_instance", asg.ResourceType)
	require.Equal(t, "CVE-2023-0286", asg.CheckID, "the CVE stays the check id so KEV matches it")
	require.Equal(t, vmVulnSource, asg.Source)
	require.Equal(t, finding.SeverityHigh, asg.Severity)
	require.Equal(t, "pkgfinding", asg.Metadata["package_finding_id"])
	require.Contains(t, asg.Remediation, "launch template")

	solo := byFleet["ami"]
	require.Equal(t, "1", solo.Metadata["affected_instances"])
	require.Equal(t, "111122223333/ami-2", solo.Metadata["fleet_id"])
	require.NotEqual(t, asg.ID, solo.ID)

	// Stable identity: the same fleet next pass is the same finding, whichever
	// member it sits on.
	fs.recorded = nil
	inv.edges = inv.edges[:4] // i-b no longer exposed
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	for _, f := range fs.recorded {
		if f.Metadata["fleet_kind"] == "asg" {
			require.Equal(t, asg.ID, f.ID)
			require.Equal(t, "i-a", f.ResourceID)
		}
	}
}

// ClickHouse hands back an open finding's resolved_at as the epoch, not Go's
// zero time. Reading that as "resolved" made every real package finding
// invisible to the fleet regroup.
func TestVMVuln_EpochResolvedAtIsOpen(t *testing.T) {
	inv := &fakeVMInventory{
		byType: map[string][]asset.Asset{"ec2_instance": {ec2("i-a", "", "ami-1", asset.PackageInventorySSM)}},
		edges:  []asset.Edge{runsPkg("i-a")},
	}
	open := pkgCVE()
	open.ResolvedAt = time.Unix(0, 0).UTC()
	fs := &fakeVMVulnFindings{byResource: map[string][]finding.Finding{testPurl: {open}}}
	require.NoError(t, (&VMVulnWorker{assets: inv, findings: fs}).Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	require.Len(t, fs.recorded, 1)
}

// package_inventory=none makes no CVE claim at all — even while runs_package
// edges from its last known inventory are still inside the freshness window —
// and a resolved package finding is no evidence either.
func TestVMVuln_NoClaimsWithoutKnownInventory(t *testing.T) {
	inv := &fakeVMInventory{
		byType: map[string][]asset.Asset{
			"ec2_instance": {ec2("i-dark", "", "ami-1", asset.PackageInventoryNone)},
			"gce_instance": {{ID: "p/vm", Type: "gce_instance", LastSeen: time.Now(), Metadata: map[string]string{}}},
		},
		edges: []asset.Edge{runsPkg("i-dark"), {SrcID: "p/vm", SrcType: "gce_instance", DstID: testPurl, EdgeType: "runs_package"}},
	}
	fs := &fakeVMVulnFindings{byResource: map[string][]finding.Finding{testPurl: {pkgCVE()}}}
	require.NoError(t, (&VMVulnWorker{assets: inv, findings: fs}).Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	require.Empty(t, fs.recorded, "no inventory, or an absent key, is never a CVE claim")

	resolvedPkg := pkgCVE()
	resolvedPkg.ResolvedAt = time.Now()
	inv.byType["ec2_instance"] = []asset.Asset{ec2("i-ok", "", "ami-1", asset.PackageInventorySSM)}
	inv.edges = []asset.Edge{runsPkg("i-ok")}
	fs.byResource[testPurl] = []finding.Finding{resolvedPkg}
	require.NoError(t, (&VMVulnWorker{assets: inv, findings: fs}).Work(context.Background(), &river.Job[RefreshVMVulnArgs]{}))
	require.Empty(t, fs.recorded, "a resolved package finding is not an open CVE")
}

func TestFleetOf(t *testing.T) {
	require.Equal(t, vmFleet{"asg", "111122223333/eu-west-1/web"}, fleetOf(ec2("i-1", "web", "ami-1", "")))
	require.Equal(t, vmFleet{"ami", "111122223333/ami-1"}, fleetOf(ec2("i-1", "", "ami-1", "")))
	require.Equal(t, vmFleet{"instance", "i-1"}, fleetOf(ec2("i-1", "", "", "")))
	gce := asset.Asset{ID: "p/web-1", AccountID: "p", Metadata: map[string]string{"instance_group": "web-mig"}}
	require.Equal(t, vmFleet{"instance_group", "p/web-mig"}, fleetOf(gce))
}
