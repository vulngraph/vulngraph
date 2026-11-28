package correlate

import (
	"iter"
	"slices"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// tfOwnershipSafeLiveTypes restricts TFOwnership to the live asset types
// whose Ladybug node label is SAFE to be a defined_in edge SOURCE — verified
// against graphstore.assetTypeToNode (buildEdgeRows routes a defined_in edge
// by NodeLabelFor(src.Type): IamRole→DefinedInIamRole,
// K8sWorkload→DefinedInK8sWorkload, anything else falls through to the default
// DefinedInAsset (Asset→Repo) table, where a source carrying any label other
// than Asset is dropped by Ladybug's endpoint label constraint) and against asset.NeverSyncTypes (a type excluded from
// Ladybug bulk sync never becomes a node at all, regardless of edge routing).
//
// A declared_tf_resource can name literally any Terraform-managed resource, so
// this list is deliberately an ALLOW-list hand-verified against both facts
// above rather than trying to derive "everything not explicitly unsafe": a
// type this list has never seen stays excluded until someone checks it.
//
// Cross-package note: correlate deliberately does not import graphstore (it
// is the worker-only Ladybug writer, per CLAUDE.md's layering rule), so this is
// a manually-verified, hand-copied subset — re-verified by
// TestTFOwnershipSafeLiveTypes_ExcludesUnsafeRoutes, which pins the excluded
// types so a future assetTypeToNode/NeverSyncTypes change is caught here too.
//
// subnet (→NodeSubnet) and elastic_ip (→NodeElasticIP) are excluded because each
// maps to its OWN node label in assetTypeToNode, not the NodeAsset catch-all, so a
// defined_in edge sourced from either would mis-route and silently drop at Ladybug
// COPY.
//
// security_group and ec2_instance stay excluded too, but as a deliberate scope
// boundary rather than a routing hazard: both route correctly to DefinedInAsset
// today, but adding them means emitting defined_in for every EC2 instance and
// security group (typically the largest live types), which is a coverage change to weigh on its own
// merits — the pin below records that boundary.
var tfOwnershipSafeLiveTypes = map[string]bool{
	"iam_role": true, // routes to DefinedInIamRole (IamRole→Repo)

	// Everything below is NOT in graphstore.assetTypeToNode, so NodeLabelFor
	// falls through to the NodeAsset catch-all and routes to DefinedInAsset
	// (Asset→Repo). None of these are in asset.NeverSyncTypes either.
	"lambda_function":       true,
	"ecs_service":           true,
	"s3_bucket":             true,
	"rds_instance":          true,
	"dynamodb_table":        true,
	"elasticache_cluster":   true,
	"secretsmanager_secret": true,
	"ssm_parameter":         true,
	"cloudsql_instance":     true,
	"cloud_function":        true,
	"cloudrun_service":      true,
	"load_balancer":         true,
	"gce_instance":          true,
	"azure_storage_account": true,
	"azure_sql_server":      true,
	"azure_sql_database":    true,
	"azure_webapp":          true,
	"azure_function":        true,
	"api_gateway":           true,
	"gcp_forwarding_rule":   true,
}

// TFOwnership joins declared_tf_resource intermediates (parsed from a repo's
// Terraform state by the GitHub tf-state ingest) to the LIVE cloud
// asset each one names, and emits a state-anchored ownership edge (live
// asset)-[:defined_in]->(github_repo).
//
// Confidence is ALWAYS "high": the join key comes directly from Terraform's own
// state (an ARN or provider-assigned id actually applied to the cloud), not a
// heuristic name guess, so a match is authoritative.
//
// Matching tries target_arn first, then target_id — ProjectDeclaredTF (see
// internal/collect/iac/project_tf.go) sets exactly one of the two per
// resource, since a StateResource always prefers ARN when the provider
// populated one.
type TFOwnership struct{}

func (TFOwnership) Name() string { return "tf_ownership" }

func (TFOwnership) InterestedIn() []string {
	types := make([]string, 0, len(tfOwnershipSafeLiveTypes)+1)
	types = append(types, "declared_tf_resource")
	for t := range tfOwnershipSafeLiveTypes {
		types = append(types, t)
	}
	return types
}

func (r TFOwnership) Correlate(g Graph) []asset.Edge { return slices.Collect(r.Edges(g)) }

func (TFOwnership) Edges(g Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {

		for _, d := range g.DeclaredTFResources() {
			repoID := d.Metadata["repo"]
			if repoID == "" {
				continue
			}
			target := d.Metadata["target_arn"]
			if target == "" {
				target = d.Metadata["target_id"]
			}
			if target == "" {
				continue
			}

			m, ok := g.AssetByID(target)
			if !ok || !tfOwnershipSafeLiveTypes[m.Type] {
				// No live match, or a live match whose type has no safe defined_in
				// route (e.g. security_group) — skip rather than emit an edge that
				// would silently drop at Ladybug load.
				continue
			}

			if !yield(asset.Edge{
				SrcID: m.ID, SrcType: m.Type,
				DstID: repoID, DstType: "github_repo",
				EdgeType: EdgeDefinedIn,
				Properties: map[string]string{
					"origin":     edgeOrigin,
					"rule":       "tf_ownership",
					"confidence": "high",
					"provenance": "iac_terraform",
					"address":    d.Metadata["address"],
				},
			}) {
				return
			}
		}
	}
}
