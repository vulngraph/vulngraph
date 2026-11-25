package graphstore

import (
	"fmt"

	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// TestEdgeUnwindTemplatesMatchRelEndpoints closes a hole the checksum gate cannot
// see. TestLadybugRelSpecMatchesDDL pins every loaded rel's endpoints to its CREATE
// REL TABLE statement, but nothing pinned the UNWIND templates to the same
// endpoints — and RunsImage's DDL once moved to FROM K8sWorkload while its template
// kept matching (s:Asset {id: r.src}), so the reference loader bound the wrong
// label for every row and the checksum happily changed with the DDL.
//
// It also pins the property keys: the template reads r.<rowKey>, and
// buildEdgeRows must produce that key. RunsImage read r.via, which buildEdgeRows
// never populates for that rel, so the image_ref column was written empty.
func TestEdgeUnwindTemplatesMatchRelEndpoints(t *testing.T) {
	for rel, spec := range ladybugRelSpec {
		q, ok := edgeUnwindQ[rel]
		require.True(t, ok, "loaded rel %q has no UNWIND template", rel)
		require.Contains(t, q, fmt.Sprintf("(s:%s {id: r.src})", quoteLabel(spec.from)),
			"rel %q: UNWIND template binds a different FROM label than its DDL declares — "+
				"the MATCH finds nothing and Ladybug silently skips every row", rel)
		require.Contains(t, q, fmt.Sprintf("(d:%s {id: r.dst})", quoteLabel(spec.to)),
			"rel %q: UNWIND template binds a different TO label than its DDL declares", rel)
		for _, p := range spec.prop {
			require.Contains(t, q, p.col+": r."+p.rowKey,
				"rel %q: UNWIND template does not read property %q from row key %q — "+
					"the column loads empty while the COPY path fills it", rel, p.col, p.rowKey)
		}
	}
}

// TestRunsImageCarriesTheImageReference pins the other half of that defect: the
// COPY path reads the image_ref row key (ladybugRelProps), and a buildEdgeRows
// that falls through to the default {src,dst,via} shape loads every RunsImage
// row with an empty image_ref.
func TestRunsImageCarriesTheImageReference(t *testing.T) {
	rows := buildEdgeRows([]asset.Edge{{
		SrcID: "c1/namespace/team/pod/api-1", SrcType: "k8s_pod",
		DstID: "img:registry/app@sha256:abc", DstType: "container_image",
		EdgeType: "runs_image", Properties: map[string]string{"image_ref": "registry/app:v1"},
	}})
	require.Len(t, rows[RelRunsImage].rows, 1)
	require.Equal(t, "registry/app:v1", rows[RelRunsImage].rows[0]["image_ref"])

	// And the COPY writer must look for it under that same key.
	require.Equal(t, []relProp{{"image_ref", "image_ref"}}, ladybugRelSpec[RelRunsImage].prop)
}

// The identity-graph reroutes. All three carry the same shape as the earlier
// label-promotion defects — a producer emitting an endpoint whose
// label the default rel table does not declare — with one difference: none of
// them had shipped, because two of these rel tables did not exist and the third
// producer has never had a row to emit.

// TestFederatedAccessFromHumanIdentityReroutesToAssetTable pins another
// instance of the class. correlate/human_identity.go emits
// human_identity -[federated_access]→ iam_role; human_identity is absent from
// assetTypeToNode so it carries the catch-all Asset label, while the default
// FederatedAccess table is Repo→IamRole. Every row would be discarded at COPY —
// and invisibly, because federated_access is not a Reach type (no security-edge
// WARN) and the github_repo-sourced rows keep the table's loaded count non-zero.
func TestFederatedAccessFromHumanIdentityReroutesToAssetTable(t *testing.T) {
	rows := buildEdgeRows([]asset.Edge{
		{SrcID: "okta:00u1", SrcType: "human_identity",
			DstID: "arn:aws:iam::1:role/admin", DstType: "iam_role",
			EdgeType: "federated_access", Properties: map[string]string{"trust_type": "oidc_email", "subject": "ada@example.com"}},
		{SrcID: "org/repo", SrcType: "github_repo",
			DstID: "arn:aws:iam::1:role/deploy", DstType: "iam_role",
			EdgeType: "federated_access", Properties: map[string]string{"trust_type": "oidc"}},
	})

	require.Len(t, rows[RelFederatedAccessAsset].rows, 1,
		"the human_identity-sourced edge must route to the Asset→IamRole table")
	require.Len(t, rows[RelFederatedAccess].rows, 1,
		"the repo-sourced edge stays on the Repo→IamRole table")

	// The federation properties must survive the reroute — a reroute that dropped
	// them would still look like a successful load.
	require.Equal(t, "oidc_email", rows[RelFederatedAccessAsset].rows[0]["trust_type"])
	require.Equal(t, "ada@example.com", rows[RelFederatedAccessAsset].rows[0]["subject"])

	spec := ladybugRelSpec[RelFederatedAccessAsset]
	require.Equal(t, NodeLabelFor("human_identity"), spec.from)
	require.Equal(t, NodeLabelFor("iam_role"), spec.to)
}

// TestMemberOfRoutesBothIdentityShapes pins the human→group→group chain: one
// edge type, two source labels, two tables. Routing both to the default
// Asset→Group table would drop the Okta→Identity Center join, which is the hop
// that connects a person to a permission set at all.
func TestMemberOfRoutesBothIdentityShapes(t *testing.T) {
	rows := buildEdgeRows([]asset.Edge{
		{SrcID: "okta:00u1", SrcType: "human_identity",
			DstID: "okta:group:g1", DstType: "sso_group", EdgeType: "member_of"},
		{SrcID: "okta:group:g1", SrcType: "sso_group",
			DstID: "sso_group:Engineering", DstType: "sso_group", EdgeType: "member_of"},
	})

	require.Len(t, rows[RelMemberOf].rows, 1, "human_identity→group must route to the Asset→Group table")
	require.Len(t, rows[RelMemberOfGroup].rows, 1, "group→group must route to the Group→Group table")

	require.Equal(t, NodeLabelFor("human_identity"), ladybugRelSpec[RelMemberOf].from)
	require.Equal(t, NodeLabelFor("sso_group"), ladybugRelSpec[RelMemberOf].to)
	require.Equal(t, NodeLabelFor("sso_group"), ladybugRelSpec[RelMemberOfGroup].from)
	require.Equal(t, NodeLabelFor("sso_group"), ladybugRelSpec[RelMemberOfGroup].to)
}

// TestExecutesAsPodToServiceAccountRoutesToItsOwnTable pins the pod→SA hop
// against BOTH executes_as tables it could have collided with: the default
// (Asset→IamRole) and the K8sWorkload reroute (K8sWorkload→IamRole), which
// matches on the source label alone and would have swallowed these rows and
// dropped every one of them on the destination.
func TestExecutesAsPodToServiceAccountRoutesToItsOwnTable(t *testing.T) {
	rows := buildEdgeRows([]asset.Edge{
		{SrcID: "c1/namespace/team/pod/api-1", SrcType: "k8s_pod",
			DstID: "c1/namespace/team/serviceaccount/api", DstType: "k8s_service_account",
			EdgeType: "executes_as"},
		// The IRSA-annotated pod: same source label, IamRole destination, stays on
		// the K8sWorkload→IamRole table.
		{SrcID: "c1/namespace/team/pod/api-1", SrcType: "k8s_pod",
			DstID: "arn:aws:iam::1:role/api", DstType: "iam_role", EdgeType: "executes_as"},
		// A non-k8s workload: unchanged on the default Asset→IamRole table.
		{SrcID: "arn:aws:lambda:eu-west-1:1:function:f", SrcType: "lambda_function",
			DstID: "arn:aws:iam::1:role/f", DstType: "iam_role", EdgeType: "executes_as"},
	})

	require.Len(t, rows[RelExecutesAsK8sServiceAccount].rows, 1)
	require.Len(t, rows["ExecutesAsK8sWorkload"].rows, 1)
	require.Len(t, rows["ExecutesAs"].rows, 1)

	spec := ladybugRelSpec[RelExecutesAsK8sServiceAccount]
	require.Equal(t, NodeLabelFor("k8s_pod"), spec.from)
	require.Equal(t, NodeLabelFor("k8s_service_account"), spec.to)
}

// TestPodServiceAccountHopIsReachable is the reason the hop was worth a schema
// bump: executes_as is a Reach type, so its new reroute target must be in
// ReachRels, or an exposed pod still fails to propagate hops into the identity
// it runs as — and from there across binds into the RBAC it holds.
func TestPodServiceAccountHopIsReachable(t *testing.T) {
	require.True(t, reachRels[RelExecutesAsK8sServiceAccount],
		"ExecutesAsK8sServiceAccount must be a reach rel — it is the pod's only path to its ServiceAccount")
	require.True(t, reachEdgeTypes["executes_as"])
	require.True(t, retentionEdgeTypes["executes_as"],
		"pod and ServiceAccount endpoints must survive filterLadybugAssets or the edge drops as endpointAbsent")
	require.True(t, retentionEdgeTypes["member_of"],
		"score-0 Okta group nodes are not in alwaysKeepTypes — without retention every membership edge drops")
}
