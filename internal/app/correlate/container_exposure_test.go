package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// TestInternetReachability_ContainerWorkloads pins the exposure half of the
// non-k8s supply-chain chain: package ← runs_package ← container_image ←
// runs_image ← {ecs_service, cloudrun_service} → exposed_to_internet. The
// collectors (collect/aws/ecs.go, collect/gcp/cloudrun.go) emit the image and
// runs_image edges; this rule must seed exactly the workloads that are
// reachable, at the tier the collector proved, so the internet-hops BFS and
// the must-fix image path reach the image's packages.
func TestInternetReachability_ContainerWorkloads(t *testing.T) {
	g := NewGraph([]asset.Asset{
		// assignPublicIp=ENABLED on an awsvpc service: a direct entry point.
		{ID: "ecs/public", Type: "ecs_service", Metadata: map[string]string{"public": "true", "assign_public_ip": "ENABLED"}},
		// Private tasks: reachable only through the ALB in front of them, which
		// the ECS collector links with load_balancer -routes_to-> ecs_service.
		{ID: "ecs/private", Type: "ecs_service", Metadata: map[string]string{"public": "false", "assign_public_ip": "DISABLED"}},
		{ID: "alb", Type: "load_balancer", Metadata: map[string]string{"public": "true"}},
		// ingress=all + allUsers run.invoker: unauthenticated, confirmed.
		{ID: "p/cloudrun/open", Type: "cloudrun_service", Metadata: map[string]string{"public": "true", "public_access": asset.PublicAccessConfirmed, "invoker_public": "true"}},
		// ingress=all, invoker IAM requires auth (or was unreadable): possible.
		{ID: "p/cloudrun/authed", Type: "cloudrun_service", Metadata: map[string]string{"public": "true", "public_access": asset.PublicAccessPossible}},
		// ingress=internal: not an internet entry point, whatever its IAM says.
		{ID: "p/cloudrun/internal", Type: "cloudrun_service", Metadata: map[string]string{"public": "false"}},
		// The shared image is never itself an entry point — it inherits reach.
		{ID: "image/sha256:abc", Type: "container_image", Name: "registry/app"},
	})

	tier := map[string]string{}
	for _, e := range (InternetReachability{}).Correlate(g) {
		require.Equal(t, InternetNodeID, e.DstID)
		require.Equal(t, "exposed_to_internet", e.EdgeType)
		tier[e.SrcID] = e.Properties[asset.EdgePropPublicAccess]
	}

	require.Equal(t, map[string]string{
		"ecs/public":        asset.PublicAccessConfirmed,
		"alb":               asset.PublicAccessConfirmed,
		"p/cloudrun/open":   asset.PublicAccessConfirmed,
		"p/cloudrun/authed": asset.PublicAccessPossible,
	}, tier, "exactly the reachable entry points seed, each at its proven tier")
}
