package correlate

import (
	"iter"
	"slices"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// EdgeConnectedViaSG records that an asset is a member of a security group (or
// Azure NSG). Membership is not a network path: two members of one AWS SG can
// talk only if an ingress rule on the target's SG names the source's SG — the
// group itself, for a self-referencing rule — or a CIDR covering it. Those
// rules are sg_allows_from edges (SecurityGroupAllows); a reachability query
// walks member -[connected_via_sg]-> SG <-[sg_allows_from]- SG
// <-[connected_via_sg]- member.
const EdgeConnectedViaSG = "connected_via_sg"

// SharedSecurityGroup emits asset→SG (spoke-hub) edges, not asset↔asset pairs:
// a full mesh is O(N²) per SG and a large shared SG can OOM the worker.
type SharedSecurityGroup struct{}

func (SharedSecurityGroup) Name() string { return "shared_security_group" }

func (SharedSecurityGroup) InterestedIn() []string {
	return []string{
		"security_group", "ec2_instance", "rds_instance", "redshift_cluster",
		"elasticache_cluster", "lambda_function", "ecs_service", "load_balancer",
		"s3_bucket", "azure_vm",
	}
}

func (r SharedSecurityGroup) Correlate(g Graph) []asset.Edge { return slices.Collect(r.Edges(g)) }

func (SharedSecurityGroup) Edges(g Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {

		for sgID, members := range g.AssetsBySG() {
			for _, a := range members {
				if !yield(asset.Edge{
					SrcID: a.ID, SrcType: a.Type,
					DstID: sgID, DstType: "security_group",
					EdgeType: EdgeConnectedViaSG,
					Properties: map[string]string{
						"origin": edgeOrigin,
						"rule":   "shared_security_group",
					},
				}) {
					return
				}
			}
		}
	}
}
