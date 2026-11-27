// Package graphstore holds the in-memory LadybugDB projection of the graph
// (upstream engine, linked unmodified; ADR 095). It serves multi-hop Cypher
// (pre-baked named queries in named_queries.go plus read-only caller queries
// checked by graphquery.IsReadOnly) and directed risk propagation computed in Go
// (bfs.go). explore falls back to a ClickHouse BFS when the RPC is unavailable.
//
// Architecture:
//   - Ladybug lives in the worker pod (single writer, ReadWriteOnce PVC safe).
//   - serve queries it via an internal RPC (handler.go exposes :8090).
//   - ClickHouse stays the authoritative source of truth; Ladybug is rebuilt from
//     it after each correlate sweep (duration is reported by
//     graph_ladybug_rebuild_duration_seconds, per phase in sync_phases.go). The
//     PVC is a disposable cache: delete it and the next correlate sweep rebuilds
//     it from ClickHouse.
package graphstore

import (
	"errors"

	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// Node labels — the node types with active collectors, aliased from
// the internal/graphschema registry, the single source of truth.
// Device, Identity, EmailDomain removed: no collectors produce them.
// DataClass re-added: synthetic sentinel nodes seeded during bulkSync (not from collectors).
const (
	NodeAsset        = graphschema.NodeAsset
	NodePackage      = graphschema.NodePackage
	NodeRepo         = graphschema.NodeRepo
	NodeIamRole      = graphschema.NodeIamRole
	NodeK8sWorkload  = graphschema.NodeK8sWorkload
	NodeSubnet       = graphschema.NodeSubnet
	NodeCloudAccount = graphschema.NodeCloudAccount
	NodeElasticIP    = graphschema.NodeElasticIP
	NodeDNSZone      = graphschema.NodeDNSZone
	NodeIamPolicy    = graphschema.NodeIamPolicy
	NodeDataClass    = graphschema.NodeDataClass
	NodeSSOGroup     = graphschema.NodeSSOGroup
	NodeSSOPermSet   = graphschema.NodeSSOPermSet
)

// Rel table names. Each rel table fixes its FROM/TO node labels.
const (
	// Semantic edges
	RelOwns          = "Owns"          // CloudAccount→Asset (collect/aws/aws.go: cloud_account owns ec2_instance)
	RelRunsIn        = "RunsIn"        // Package→Asset
	RelDeployedBy    = "DeployedBy"    // Asset→Repo
	RelCanEscalateTo = "CanEscalateTo" // IamRole→IamRole
	RelAccesses      = "Accesses"      // Asset→Asset
	RelContainsData  = "ContainsData"  // Asset→DataClass
	RelRunsPackage   = "RunsPackage"   // Asset→Package
	RelExecutesAs    = "ExecutesAs"    // Asset→IamRole

	// Computed edges (from graph correlate rules)
	RelExposedToInternet = "ExposedToInternet" // Asset→Asset (sentinel)
	// RelExposedToInternetK8sWorkload is the K8sWorkload-sourced half of
	// exposed_to_internet: a pod/deployment directly reachable from the internet
	// (hostNetwork, NodePort, a LoadBalancer service resolving straight to it).
	// k8s_pod/k8s_deployment are K8sWorkload-labeled, so these rows cannot
	// live in the Asset→Asset table.
	RelExposedToInternetK8sWorkload = "ExposedToInternetK8sWorkload" // K8sWorkload→Asset
	RelHasRole                      = "HasRole"                      // Asset→IamRole
	RelConnectedViaSG               = "ConnectedViaSG"               // Asset→Asset: member → security_group (membership, not a path)
	RelAllowsFrom                   = "AllowsFrom"                   // Asset→Asset: src permits ingress from dst (SG→SG, self-loop for a self-reference; GCP instance→instance)
	RelPeeredWith                   = "PeeredWith"                   // Asset→Asset
	RelDeploysTo                    = "DeploysTo"                    // Repo→K8sWorkload (k8s pods/deployments)
	RelDeploysToService             = "DeploysToService"             // Repo→Asset (ECS, Lambda, Cloud Run, Azure Web Apps)
	RelAllowsAction                 = "AllowsAction"                 // IamRole→IamPolicy (dangerous permission detected)
	RelDependsOn                    = "DependsOn"                    // Repo→Package (SBOM: repo depends on package)
	RelCanAssume                    = "CanAssume"                    // IamRole→IamRole
	RelProtectedBy                  = "ProtectedBy"                  // Asset→Asset
	RelDnsPointsTo                  = "DnsPointsTo"                  // Asset→Asset
	RelFederatedAccess              = "FederatedAccess"              // Repo→IamRole (GitHub OIDC, IRSA, WIF)
	// RelFederatedAccessK8sWorkload is the K8sWorkload-sourced half of
	// federated_access: a GKE/EKS ServiceAccount federating into a cloud role
	// (Workload Identity / IRSA). k8s_service_account is K8sWorkload-labeled, so
	// these rows cannot live in the Repo→IamRole table.
	RelFederatedAccessK8sWorkload = "FederatedAccessK8sWorkload" // K8sWorkload→IamRole
	// RelFederatedAccessAsset is the Asset-sourced half of federated_access: a
	// human_identity (Okta/Google) federating into a cloud role. human_identity is
	// not in assetTypeToNode, so it carries the catch-all Asset label and cannot
	// live in the Repo→IamRole table.
	RelFederatedAccessAsset = "FederatedAccessAsset" // Asset→IamRole
	// RelOwnsAsset is the Asset-sourced half of owns: a human_identity (Okta/
	// Google, correlate/human_identity.go) owning a github_repo. human_identity is
	// not in assetTypeToNode, so it carries the catch-all Asset label and cannot
	// live in the CloudAccount→Asset Owns table.
	RelOwnsAsset        = "OwnsAsset"        // Asset→Repo
	RelInVPC            = "InVPC"            // Asset→Asset (subnet/EC2/SG in a VPC)
	RelAccessesSecret   = "AccessesSecret"   // IamRole→Asset (SA can read GCP secret)
	RelBinds            = "Binds"            // Asset→Asset (ClusterRoleBinding→ClusterRole)
	RelBindsK8sWorkload = "BindsK8sWorkload" // K8sWorkload→Asset (ServiceAccount→ClusterRoleBinding)
	RelRunsImage        = "RunsImage"        // K8sWorkload(k8s_pod)→Asset(container_image)
	RelRunsImageAsset   = "RunsImageAsset"   // Asset(ecs_service/cloudrun_service)→Asset(container_image)
	RelHasPolicy        = "HasPolicy"        // Asset→IamPolicy
	RelInSubnet         = "InSubnet"         // Asset→Subnet
	RelMemberOfZone     = "MemberOfZone"     // Asset→DNSZone

	// RelExecutesAsK8sServiceAccount is the pod→ServiceAccount hop: both endpoints
	// promote to K8sWorkload, so neither ExecutesAs (Asset→IamRole) nor
	// ExecutesAsK8sWorkload (K8sWorkload→IamRole) can hold these rows.
	RelExecutesAsK8sServiceAccount = "ExecutesAsK8sServiceAccount" // K8sWorkload→K8sWorkload

	// Identity group membership
	RelMemberOf      = "MemberOf"      // Asset→Group (human_identity → IdP group)
	RelMemberOfGroup = "MemberOfGroup" // Group→Group (Okta group → Identity Center group)

	// SSO graph
	RelAssignedTo     = "AssignedTo"     // Group→PermissionSet
	RelGrantsAccessTo = "GrantsAccessTo" // PermissionSet→CloudAccount
	RelGrantsAdmin    = "GrantsAdmin"    // PermissionSet→CloudAccount

	// IaC ownership
	RelDefinedInK8sWorkload = "DefinedInK8sWorkload" // K8sWorkload→Repo
	RelDefinedInAsset       = "DefinedInAsset"       // Asset→Repo

	// IaC ownership: IAM role declared in a repo (Terraform state, identifier harvest)
	RelDefinedInIamRole = "DefinedInIamRole" // IamRole→Repo
)

// edgeTypeToRel maps the edge_type values produced by correlate/collectors to
// Ladybug rel table names. Unknown edge types fall back to the generic Edge table.
// Derived from the internal/graphschema registry — edit the registry,
// not this map. Routing rationale lives there: sg_allows_from→AllowsFrom (trust
// direction), runs_in/targets/routes_to→Accesses (generic containment; the
// package-sourced runs_in reroute to RunsIn happens in buildEdgeRows).
var edgeTypeToRel = graphschema.EdgeTypeToRel()

// assetTypeToNode maps asset type strings to Ladybug node table names.
// All asset types not listed here map to NodeAsset (the catch-all).
//
// Adding an entry here is a load-time hazard, not a cosmetic choice: promoting a
// type off Asset makes every rel table declared FROM/TO Asset silently discard
// edges whose endpoint is that type, because the loader's `MATCH (s:Asset {id})`
// no longer finds the node (see producer_label_test.go). Promote a type only
// when it needs columns Asset does not have (as NodeIamRole does: exposed,
// has_kev, internet_hops, trust_entry), and add the producer triples to
// producerEdges in the same change.
var assetTypeToNode = map[string]string{
	"iam_role":                NodeIamRole,
	"iam_user":                NodeIamRole,
	"iam_group":               NodeIamRole,
	"gcp_service_account":     NodeIamRole,
	"azure_service_principal": NodeIamRole,
	"azure_managed_identity":  NodeIamRole,
	"github_repo":             NodeRepo,
	"package":                 NodePackage,
	"k8s_pod":                 NodeK8sWorkload,
	"k8s_deployment":          NodeK8sWorkload,
	"k8s_daemonset":           NodeK8sWorkload,
	"k8s_statefulset":         NodeK8sWorkload,
	"k8s_job":                 NodeK8sWorkload,
	"k8s_service_account":     NodeK8sWorkload,
	"subnet":                  NodeSubnet,
	"cloud_account":           NodeCloudAccount,
	// elastic_ip → NodeAsset, not NodeElasticIP: NodeElasticIP is declared in
	// the DDL but never populated by the loader, so under it an Elastic IP would
	// exist as an asset and never as a graph node — silently dropping
	// dns_points_to edges that terminate on it. Keeping the type out of
	// NeverSyncTypes is not enough on its own: under the typed label the drops
	// would just move from endpointAbsent to label_mismatch.
	"elastic_ip": NodeAsset,
	// dns_zone and iam_policy → NodeAsset for the same reason: NodeDNSZone and
	// NodeIamPolicy are declared but never populated. Nothing is lost: the only
	// rel tables naming them (MemberOfZone, HasPolicy, AllowsAction) are unfed by
	// design, and neither type carries a risk score, so with dns_zone outside
	// alwaysKeepTypes both are pruned instead of promoted.
	"dns_zone":           NodeAsset,
	"iam_policy":         NodeAsset,
	"data_class":         NodeDataClass,
	"sso_group":          NodeSSOGroup,
	"sso_permission_set": NodeSSOPermSet,
}

// NodeLabelFor returns the Ladybug node table for a given asset type.
func NodeLabelFor(assetType string) string {
	if label, ok := assetTypeToNode[assetType]; ok {
		return label
	}
	return NodeAsset
}

// RelTableFor returns the Ladybug rel table for a given edge type, plus whether
// it was a known type (false = falls back to generic Edge table).
func RelTableFor(edgeType string) (string, bool) {
	if rel, ok := edgeTypeToRel[edgeType]; ok {
		return rel, true
	}
	return "Edge", false
}

// SchemaVersion is bumped whenever the DDL or the loading set (which rows the
// loader fetches/populates) changes. It gates the PVC snapshot: ReadSnapshot
// rejects a snapshot built under a different version, forcing a full rebuild
// from ClickHouse rather than silently loading against a shape the running
// binary no longer shares. A loading-set-only change needs the bump just as
// much as a DDL change — restoring an old snapshot after one would serve a
// different (not merely older) set of rows. (The _SchemaMeta node is written
// for debugging only — every boot opens a fresh :memory: DB with current DDL,
// so there is no in-place migration to detect.)
//
// A bug class to check on every bump: a node label gets promoted off
// the generic Asset/K8sWorkload catch-all, but a rel table declared FROM/TO the
// old label is not rerouted, so the loader's node-match silently discards every
// edge on that endpoint. See producer_label_test.go and the assetTypeToNode
// comment above.
const SchemaVersion = "v4"

// SchemaDDLChecksum pins a hash of the Ladybug DDL — node/rel CREATE statements plus
// the UNWIND insert templates. TestSchemaDDLChecksum recomputes it and fails if it
// drifts, forcing a conscious SchemaVersion bump whenever the schema changes: a
// stale PVC snapshot or a cross-pod replica would otherwise load against the wrong
// shape with no error. When you change the DDL, bump SchemaVersion AND update this
// checksum in the same commit (the test prints the new value on failure).
const SchemaDDLChecksum = "0bbdc48386fccde5"

// Sentinel node ID for the internet in ExposedToInternet edges.
const InternetNodeID = "internet"

var (
	ErrLadybugUnavailable = errors.New("graphstore: ladybug unavailable")
	ErrSchemaMismatch     = errors.New("graphstore: schema version mismatch — rebuild required")
	ErrReadOnly           = errors.New("graphstore: write operations not permitted on query connection")
	ErrBudgetExceeded     = errors.New("graphstore: node/edge budget exceeded")
	ErrSnapshotMissing    = errors.New("graphstore: snapshot file not found — cold start from ClickHouse")
	ErrSnapshotStale      = errors.New("graphstore: snapshot schema or topology version mismatch — rebuild required")
	// ErrRebuildRefused means a candidate rebuild failed the fidelity gate and was
	// ABANDONED: the previous graph is still serving, unchanged. It is deliberately
	// an error and not a silent skip — the correlate job must fail visibly, because
	// a graph that stops advancing needs an operator, and the alternative (publish
	// anyway) is the failure this gate exists to prevent. See fidelity.go.
	ErrRebuildRefused = errors.New("graphstore: rebuild refused by the fidelity gate — previous graph still serving")
)

// QueryBudget caps Cypher query results to prevent runaway traversals. Clamp
// maps 0 or anything above HardBudget to HardBudget; the API's 500/2000
// defaults are applied by explore before a query reaches here.
type QueryBudget struct {
	MaxNodes int // hard max 2000
	MaxEdges int // hard max 5000
}

var DefaultBudget = QueryBudget{MaxNodes: 500, MaxEdges: 2000}
var HardBudget = QueryBudget{MaxNodes: 2000, MaxEdges: 5000}

func (b QueryBudget) Clamp() QueryBudget {
	if b.MaxNodes <= 0 || b.MaxNodes > HardBudget.MaxNodes {
		b.MaxNodes = HardBudget.MaxNodes
	}
	if b.MaxEdges <= 0 || b.MaxEdges > HardBudget.MaxEdges {
		b.MaxEdges = HardBudget.MaxEdges
	}
	return b
}
