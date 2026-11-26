package enrich

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// containerWorkloadLineage is the graph_edges shape the ECS and Cloud Run
// collectors produce for one image (collect/aws/ecs.go, collect/gcp/cloudrun.go),
// plus the imagevuln scanner's runs_package edge and correlate's exposure edge:
//
//	package ← runs_package ← image ← runs_image ← workload → exposed_to_internet
func containerWorkloadLineage(pkg, img, workload string, exposed bool) fakeLineage {
	g := fakeLineage{
		into: map[string][]asset.Edge{
			pkg: {{SrcID: img, SrcType: "container_image", DstID: pkg, DstType: "package", EdgeType: "runs_package"}},
			img: {{SrcID: workload, DstID: img, DstType: "container_image", EdgeType: "runs_image"}},
		},
		from: map[string][]asset.Edge{workload: nil},
	}
	if exposed {
		g.from[workload] = []asset.Edge{{SrcID: workload, DstID: "internet", EdgeType: "exposed_to_internet"}}
	}
	return g
}

// TestSupplyChainExposure_NonK8sWorkloads: the image lineage is not k8s-only.
// An image CVE running on a public ECS service or an internet-ingress Cloud Run
// service resolves exactly like one on an exposed pod; a private one is
// deployed but contained.
func TestSupplyChainExposure_NonK8sWorkloads(t *testing.T) {
	const pkg = "pkg:deb/debian/openssl@3.0.11-1~deb12u1"
	const img = "image/sha256:abc"
	tests := []struct {
		name        string
		workload    string
		exposed     bool
		wantExposed bool
	}{
		{"public ECS service", "arn:aws:ecs:eu-west-1:1:service/prod/web", true, true},
		{"private ECS service", "arn:aws:ecs:eu-west-1:1:service/prod/worker", false, false},
		{"internet-ingress Cloud Run service", "proj/cloudrun/api", true, true},
		{"internal-ingress Cloud Run service", "proj/cloudrun/jobs", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := containerWorkloadLineage(pkg, img, tt.workload, tt.exposed)
			anyDeployed, anyExposed, _, err := SupplyChainExposure{Graph: g}.PackageDeployExposure(context.Background(), pkg)
			require.NoError(t, err)
			require.True(t, anyDeployed, "a running ECS/Cloud Run service is a deployment")
			require.Equal(t, tt.wantExposed, anyExposed)
		})
	}
}

// TestAssessMustFix_ExposedECSServiceWithKEVPackage is the end-to-end case the
// ECS image coverage exists for: a KEV-listed CVE in a package inside an image
// that a publicly reachable ECS service runs must classify elevated — through
// the ClickHouse lineage alone (Ladybug down) and through the internet-hops BFS
// alone (an ALB-fronted service, whose exposure is one routes_to hop away and
// so only the BFS sees it).
func TestAssessMustFix_ExposedECSServiceWithKEVPackage(t *testing.T) {
	const pkg = "pkg:deb/debian/openssl@3.0.11-1~deb12u1"
	f := finding.Finding{
		Source: "supply_chain", Type: "vulnerable_dependency",
		ResourceType: "package", ResourceID: pkg,
		CheckID: "CVE-2023-0286", Severity: finding.SeverityHigh,
		KnownExploited: true,
	}

	t.Run("public ECS service via ClickHouse lineage", func(t *testing.T) {
		g := containerWorkloadLineage(pkg, "image/sha256:abc", "arn:aws:ecs:eu-west-1:1:service/prod/web", true)
		class, reason := assessMustFix(context.Background(), f, asset.Asset{}, nil, nil,
			SupplyChainExposure{Graph: g}, nil, nil, time.Now())
		require.Equal(t, MustFixElevated, class)
		require.NotEmpty(t, reason)
	})

	t.Run("ALB-fronted ECS service via internet-hops BFS", func(t *testing.T) {
		// CH lineage sees a deployed-but-not-directly-exposed service; the BFS
		// reaches the package at 1 hop (internet → ALB → routes_to → service,
		// then containment through runs_image/runs_package).
		g := containerWorkloadLineage(pkg, "image/sha256:abc", "arn:aws:ecs:eu-west-1:1:service/prod/api", false)
		class, reason := assessMustFix(context.Background(), f, asset.Asset{}, fakeReach{hops: 1, ok: true}, nil,
			SupplyChainExposure{Graph: g}, nil, nil, time.Now())
		require.Equal(t, MustFixElevated, class)
		require.NotEmpty(t, reason)
	})

	t.Run("private ECS service with no LB: a KEV package is never contained", func(t *testing.T) {
		g := containerWorkloadLineage(pkg, "image/sha256:abc", "arn:aws:ecs:eu-west-1:1:service/prod/worker", false)
		class, reason := assessMustFix(context.Background(), f, asset.Asset{}, nil, nil,
			SupplyChainExposure{Graph: g}, nil, nil, time.Now())
		require.Equal(t, MustFixElevated, class, "KEV is exploitable from any internal foothold")
		require.Contains(t, reason, "KEV")

		notKEV := f
		notKEV.KnownExploited = false
		class, _ = assessMustFix(context.Background(), notKEV, asset.Asset{}, nil, nil,
			SupplyChainExposure{Graph: g, Reach: fakeReach{hops: reachNone, ok: true}}, nil, nil, time.Now())
		require.Equal(t, MustFixContained, class)
	})
}
