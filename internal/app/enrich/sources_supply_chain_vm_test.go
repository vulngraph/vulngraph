package enrich

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// vmFleetFinding is the shape internal/jobs/vmvuln.go records: a package CVE
// placed on a member VM of its fleet.
func vmFleetFinding(kev bool) finding.Finding {
	return finding.Finding{
		ID: "fleet-1", Source: "vm_vuln", Type: "vulnerable_package", Severity: finding.SeverityHigh,
		ResourceType: "ec2_instance", ResourceID: "i-web", CheckID: "CVE-2023-0286",
		KnownExploited: kev,
		Metadata:       map[string]string{"fleet_kind": "asg", "affected_instances": "12"},
	}
}

// The headline: an internet-exposed EC2 running a KEV package is must_fix through
// the EXISTING classifier — reachable, exploited, real blast, live — with no
// VM-specific rule. Unexposed is never must_fix (but an exploited CVE is never
// demoted to contained either), and an unexploited CVE is not urgent.
func TestAssessMustFix_VMFleetCVE(t *testing.T) {
	ctx := context.Background()
	seed := asset.Asset{ID: "i-web", Type: "ec2_instance", LastSeen: time.Now()}
	blast := fakeCounter{count: 20}

	class, reason := assessMustFix(ctx, vmFleetFinding(true), seed, fakeReach{hops: 0, ok: true}, blast, nil, nil, nil, time.Now())
	require.Equal(t, MustFix, class)
	require.Contains(t, reason, "internet-exposed")
	require.Contains(t, reason, "KEV")

	class, reason = assessMustFix(ctx, vmFleetFinding(true), seed, fakeReach{hops: reachNone, ok: true}, blast, nil, nil, nil, time.Now())
	require.Equal(t, MustFixElevated, class, "an unexposed KEV host is urgent but not must_fix")
	require.Contains(t, reason, "not reachable from the internet")

	class, _ = assessMustFix(ctx, vmFleetFinding(false), seed, fakeReach{hops: 0, ok: true}, blast, nil, nil, nil, time.Now())
	require.NotEqual(t, MustFix, class, "exposure alone is not exploitability")
	require.NotEqual(t, MustFixElevated, class)
}

// The package-level supply_chain finding on a VM-installed package walks the VM
// lineage: the VM is the workload, so its own exposed_to_internet edge decides —
// it is never mistaken for an image and sent looking for a pod.
func TestSupplyChainExposure_VMLineage(t *testing.T) {
	pkg := "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10"
	f := finding.Finding{Source: "supply_chain", ResourceType: "package", ResourceID: pkg}
	exposed := fakeLineage{
		into: map[string][]asset.Edge{pkg: {{SrcID: "i-web", SrcType: "ec2_instance", DstID: pkg, EdgeType: "runs_package"}}},
		from: map[string][]asset.Edge{"i-web": {{SrcID: "i-web", DstID: "internet", EdgeType: "exposed_to_internet"}}},
	}
	factor, applied, err := SupplyChainExposure{Graph: exposed}.Evaluate(context.Background(), f)
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, 20, factor.Points)
	require.Equal(t, ThresholdPipeline, factor.Floor)

	internal := fakeLineage{
		into: map[string][]asset.Edge{pkg: {{SrcID: "i-batch", SrcType: "gce_instance", DstID: pkg, EdgeType: "runs_package"}}},
	}
	deployed, isExposed, _, err := SupplyChainExposure{Graph: internal}.PackageDeployExposure(context.Background(), pkg)
	require.NoError(t, err)
	require.True(t, deployed, "an inventoried VM is a deployed workload")
	require.False(t, isExposed)

	// A VM and an image on the same package: either exposure is enough.
	mixed := fakeLineage{
		into: map[string][]asset.Edge{
			pkg:              {{SrcID: "image/sha256:a", DstID: pkg, EdgeType: "runs_package"}, {SrcID: "i-web", SrcType: "ec2_instance", DstID: pkg, EdgeType: "runs_package"}},
			"image/sha256:a": {{SrcID: "cluster/pod/ns/batch", DstID: "image/sha256:a", EdgeType: "runs_image"}},
		},
		from: map[string][]asset.Edge{"i-web": {{SrcID: "i-web", DstID: "internet", EdgeType: "exposed_to_internet"}}},
	}
	_, isExposed, _, err = SupplyChainExposure{Graph: mixed}.PackageDeployExposure(context.Background(), pkg)
	require.NoError(t, err)
	require.True(t, isExposed)
}

// Through the package path the VM's inherited hop count reads as runtime
// reachability, and the reason no longer claims it came from a container image.
func TestAssessSupplyChainMustFix_RuntimeReachReason(t *testing.T) {
	f := finding.Finding{Source: "supply_chain", ResourceType: "package", ResourceID: "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10"}
	class, reason := assessSupplyChainMustFix(context.Background(), f, nil, fakeReach{hops: 0, ok: true})
	require.Equal(t, MustFixElevated, class)
	require.Contains(t, reason, "VM")
	require.True(t, ReachabilityEvidenced(class, reason))
}

type fakeFleetLister struct {
	findings []finding.Finding
	err      error
}

func (f fakeFleetLister) List(_ context.Context, flt finding.Filter) ([]finding.Finding, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []finding.Finding
	for _, x := range f.findings {
		if x.Source == flt.Source && x.CheckID == flt.CheckID {
			out = append(out, x)
		}
	}
	return out, nil
}

// A vulnerable package is ONE finding per remediation unit. Run only by
// inventoried VMs, the per-fleet vm_vuln findings are canonical: the package
// finding stops scoring the hosts (no exposure points, no floor) as long as the
// fleets cover every VM runner. Anything else keeps the package finding's own
// evaluation: an image or repo also running it, a VM the fleet job did not
// group, or no fleet finding at all.
func TestSupplyChainExposure_FleetCanonical(t *testing.T) {
	pkg := "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10"
	f := finding.Finding{ID: "pkg-f", Source: "supply_chain", ResourceType: "package", ResourceID: pkg, CheckID: "CVE-2023-0286"}
	runs := func(srcs ...asset.Edge) fakeLineage {
		return fakeLineage{
			into: map[string][]asset.Edge{pkg: srcs},
			from: map[string][]asset.Edge{"i-a": {{SrcID: "i-a", DstID: "internet", EdgeType: "exposed_to_internet"}}},
		}
	}
	vm := func(id string) asset.Edge {
		return asset.Edge{SrcID: id, SrcType: "ec2_instance", DstID: pkg, EdgeType: "runs_package"}
	}
	fleet := func(id, pkgFinding, instances string) finding.Finding {
		return finding.Finding{ID: id, Source: "vm_vuln", CheckID: f.CheckID,
			Metadata: map[string]string{"package_finding_id": pkgFinding, "affected_instances": instances}}
	}
	twoFleets := fakeFleetLister{findings: []finding.Finding{fleet("fl-1", "pkg-f", "1"), fleet("fl-2", "pkg-f", "1"), fleet("other", "pkg-other", "40")}}

	tests := []struct {
		name          string
		graph         fakeLineage
		fleets        FleetFindingLister
		wantCanonical bool
	}{
		{"VM-only, every runner covered", runs(vm("i-a"), vm("i-b")), twoFleets, true},
		{"VM-only, a runner not grouped by the fleet job", runs(vm("i-a"), vm("i-b"), vm("i-c")), twoFleets, false},
		{"an image also runs it", runs(vm("i-a"), asset.Edge{SrcID: "img", SrcType: "container_image", DstID: pkg, EdgeType: "runs_package"}), twoFleets, false},
		{"a repo depends on it", runs(vm("i-a"), asset.Edge{SrcID: "org/app", DstID: pkg, EdgeType: "depends_on"}), twoFleets, false},
		{"no fleet findings yet", runs(vm("i-a")), fakeFleetLister{}, false},
		{"no lister wired", runs(vm("i-a")), nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := SupplyChainExposure{Graph: tt.graph, Fleets: tt.fleets}
			canonical, _, err := s.FleetCanonical(context.Background(), f)
			require.NoError(t, err)
			require.Equal(t, tt.wantCanonical, canonical)

			factor, applied, err := s.Evaluate(context.Background(), f)
			require.NoError(t, err)
			require.True(t, applied)
			if tt.wantCanonical {
				require.Zero(t, factor.Points, "the fleet findings score the hosts; the package must not score them again")
				require.Zero(t, factor.Floor)
				require.Contains(t, factor.Detail, "vm_vuln")
			} else {
				require.Positive(t, factor.Points, "the package finding keeps its own evaluation")
			}
		})
	}

	_, _, err := SupplyChainExposure{Graph: runs(vm("i-a")), Fleets: fakeFleetLister{err: context.DeadlineExceeded}}.FleetCanonical(context.Background(), f)
	require.Error(t, err, "a failed fleet read is an error, never a coverage claim")
}
