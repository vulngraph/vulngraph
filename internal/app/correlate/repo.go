package correlate

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// correlationTypes are the asset types correlation needs in the view: DNS
// records (the join's left side) plus every type a record can resolve to, the
// IAM roles for can_assume, and the github repos + k8s workloads for deploys_to.
var correlationTypes = []string{
	"dns_record", "ec2_instance", "elastic_ip", "load_balancer", "gce_instance",
	"iam_role",
	"github_repo", "k8s_pod", "k8s_deployment", "k8s_service",
	// k8s workload kinds — needed by K8sManifestOwnership to
	// join declared manifests to live StatefulSet/DaemonSet/Job assets.
	"k8s_statefulset", "k8s_daemonset", "k8s_job",
	// declared_k8s_workload: the manifest-ingest intermediate the ownership rule reads.
	"declared_k8s_workload",
	// declared_ci_access: the GitHub-workflow-parse intermediate CIAccess reads.
	// iam_role/gcp_service_account (its live join targets) are
	// already above for other rules' sake.
	"declared_ci_access", "github_workflow",
	// declared_cloud_identity: the generic identifier-harvest intermediate
	// DeclaredIdentityOwnership reads. Its absence here would mean the rule
	// only ever sees edges from PartialCorrelate (which loads types from the
	// rules' InterestedIn, not this list), so they'd age out entirely under
	// the 48h edge-freshness rule the moment the IaC sync paused.
	"declared_cloud_identity",
	// declared_tf_resource: the Terraform-state-parse intermediate TFOwnership
	// reads. Its live join targets (tfOwnershipSafeLiveTypes) are
	// already covered above/below for other rules' sake.
	"declared_tf_resource",
	// declared_image_build + container_image: the image-reference intermediate
	// ImageOwnership reads and the live images it joins them to. Unlike the
	// other declared_* pairs, BOTH sides are listed here: no other rule reads
	// container_image.
	"declared_image_build", "container_image",
	// Topology / reachability.
	"security_group", "gcp_firewall",
	"cloudsql_instance", "cloudrun_service", "cloud_function",
	// Internet entry points.
	"gcp_forwarding_rule", "api_gateway", "ecs_service", "lambda_function",
	// Azure assets.
	"azure_vm", "azure_public_ip",
	"azure_webapp", "azure_app_gateway", "azure_storage_account",
	"azure_sql_server", "azure_sql_database",
	// Connected-service blast radius + DNS reachability.
	"rds_instance",     // SG membership + publicly_accessible findings
	"redshift_cluster", // SG membership
	"s3_bucket",        // Domain already set by collector; DNS resolution + public findings
	"iam_user",         // IAMCanAssume emits edges from users
	// TFOwnership safe-list live types not already covered above.
	"dynamodb_table", "elasticache_cluster", "azure_function",
	// K8s external attack surface.
	"k8s_ingress", // externally-reachable hostnames; routes_to edges to services
	// GCP principals — required for ExecutesAs (GCE→SA) and GKE WIF correlation.
	// Without these, gcp_service_account IDs fail g.IsPrincipal() checks and
	// every GCE/GKE executes_as edge is silently dropped.
	"gcp_service_account",
	"k8s_service_account",
	// eks_cluster: the OIDC-issuer side of the IRSA join (IRSATrust). Without it
	// no role's federated_provider can be attributed to a cluster and the rule is
	// dead on the full sweep. It is ALSO an internet entry point in its own right
	// — see the cluster case in NewGraph.
	"eks_cluster",
	// gke_cluster: an entry point only, with no IRSA equivalent here (GKE
	// Workload Identity is joined through k8s_service_account).
	"gke_cluster",
	// Storage assets for DSPM data classification and DNS resolution.
	"gcs_bucket",
	// Secret stores — for accesses_secret correlation (IAM role → secret it can read)
	// and DSPM classification of secret-named stores.
	"secretsmanager_secret", "ssm_parameter", "gcp_secret",
	// aws_scp_set: the organization SCP documents. NewGraph indexes them into
	// scpPoliciesByAccount, which IAMEffectivePermissions and SecretAccess
	// read via SCPPoliciesForAccount — must stay in this list or that map is
	// always empty and the org-level cap never applies to any derived edge.
	"aws_scp_set",
	// vpc_network: read by GCPFirewallApplies (declared in its InterestedIn).
	"vpc_network",
	// Azure principals — ExecutesAs targets; without them g.IsPrincipal() fails
	// and every azure executes_as edge is silently dropped (as with
	// gcp_service_account above).
	"azure_service_principal", "azure_managed_identity",
	// human_identity: HumanIdentityFederation's left side (Okta/Google/GitHub).
	"human_identity",
	// Remaining DataClassification storage types.
	"azure_blob_container", "firestore_collection", "cloud_sql_instance",
	// kms_key/ecr_repository/sqs_queue/sns_topic: their resource-policy exposure
	// checks (aws-kms-key-policy-public etc.) run over ClickHouse directly, so
	// they fire regardless of this view — but a leaked resource policy still
	// needs the type present here, in asset.NeverSyncTypes' opposite, and in
	// InternetReachability.InterestedIn (see the case comment in NewGraph) to
	// reach the internet-hops BFS.
	"kms_key", "ecr_repository", "sqs_queue", "sns_topic",
	// ebs_snapshot/rds_snapshot/ami/gcp_image/gcp_disk_snapshot/azure_disk: same
	// gap, different shape — their "public" checks run over ClickHouse directly
	// too, but these six need to be present here and in
	// InternetReachability.InterestedIn to have any graph presence beyond the
	// bare asset node. Unlike kms_key/ecr_repository/sqs_queue/sns_topic above,
	// none of the six is in asset.NeverSyncTypes, so only the correlate wiring
	// was missing, not a schema change.
	"ebs_snapshot", "rds_snapshot", "ami", "gcp_image", "gcp_disk_snapshot", "azure_disk",
}

// correlationLimit is a CIRCUIT BREAKER, not a truncation point — crossing it
// fails the sweep with ErrViewTruncated, because a rule that cannot see an
// endpoint stops re-stamping its edge and the edge leaves the graph within the
// 48h freshness window. A truncated sweep must refuse rather than silently
// drop topology.
//
// The value assumes a large worker; it is not derived from the chart default.
// At an unmeasured estimate of ~5 KiB per decoded asset.Asset row (metadata
// as a Go map), 600k rows is ~3 GiB, which fits a 35% view budget only with a
// Go limit near 8 GiB (a worker cgroup of ~10 GiB, set via worker.resources
// and worker.goMemLimit in the Helm values). The default worker (4Gi limit,
// 1280Mi Ladybug pool, 1024Mi reserve: a ~1.8 GiB Go limit, see
// internal/memlimit) can run out of memory before this breaker trips.
//
// Raising it trades silent truncation for a worker OOM. The metadata-key
// projection below is the next lever if headroom runs out, not a bigger
// number here.
const correlationLimit = 600_000

// loadViewTimeout bounds the correlation read. It is NOT a query-execution
// bound: ClickHouse computes this aggregate in a few seconds, but the result
// is hundreds of MiB and scanAssets json.Unmarshals metadata for every row
// inline in the scan loop, so wall time is dominated by streaming to a slow
// client. 5 minutes leaves most of the CorrelateWorker's 20-minute budget for
// the rules, the edge ingest and the post-correlate steps.
const loadViewTimeout = 5 * time.Minute

// metadataProjectedKeys are the ONLY metadata keys any correlation rule
// reads — an exhaustive grep of `.Metadata["…"]` across
// internal/app/correlate/*.go (excluding _test.go). This is the "next lever"
// mentioned above: metadata is a large share of the view's wire cost, most of
// it in "permissions" and "policies" — both genuinely read (gcp_impersonation.go,
// iam.go, irsa.go, federation.go, secret_access.go, iam_permissions.go,
// human_identity.go), so this list keeps them; it drops the rest of what
// metadata carries that no rule ever looks at.
//
// TestLoadViewProjectsAllReadMetadataKeys ASTs this package and fails the
// build if a rule starts reading a Metadata["…"] key not listed here — that
// is the safety net that makes a silent drop (a rule reading a key that was
// server-side-projected away) impossible to ship unnoticed. Add the key here
// FIRST, in the same commit as the rule change that starts reading it.
var metadataProjectedKeys = []string{
	"workflow_id", "coverage", "condition",
	"account_id", "address", "allowed", "custom_name", "denied", "deny_world", "direction",
	"destination_ranges", "firewall_rules_complete", "network_interfaces", "nsg_rules_complete", "network_interfaces_complete", "direct_public_ip",
	"disabled", "drift", "exec_role", "external_ip_configured", "federated_provider",
	"iam_role_arn", "in_public_subnet", "in_public_subnet_v6", "iam.gke.io/gcp-service-account", "image", "images", "ingress", "ingress_rules",
	"internet_exportable", "ipv6_addresses", "kind", "live_type", "manifest_key", "match", "namespace",
	"network", "network_tags", "nic_nsgs", "nsg_ids", "oidc_issuer", "oidc_provider_arn",
	"organization_membership", "organization_policies", "open_to_internet", "owner_kind", "owner_name", "path", "permission_boundary_complete", "permissions",
	"physical_name", "policies", "policies_complete", "priority", "project", "provider", "public",
	"public_access", "publicly_accessible", "repo", "scheme_assumed", "security_groups", "selector",
	"service_account", "source_ranges", "source_sas", "source_restricted", "source_tags", "target_arn", "target_id", "target_sa",
	"target_sas", "target_tags", "type", "value", "values", "workflow_path",
}

// projectMetadataExpr wraps an argMax(metadata, synced_at) aggregate with a
// server-side key projection: JSONExtract parses the JSON-object column into
// a typed Map(String,String) (matching decodeMeta's own assumption that
// every metadata value is a flat string — a JSON value that weren't would
// already fail decodeMeta's json.Unmarshal client-side today), mapFilter
// drops every key not in metadataProjectedKeys, and toJSONString re-encodes
// the result — properly escaping string values, which matters here because
// "policies"/"permissions" values are themselves serialized JSON text.
// Unprojected keys never cross the wire at all; this is what cuts the
// metadata column's bytes, not just what scanAssets does with them.
const projectMetadataExpr = `toJSONString(mapFilter((k, v) -> k IN (%s), JSONExtract(argMax(metadata, synced_at), 'Map(String, String)')))`

// loadView selects the minimal columns correlation needs (id, type, account_id,
// public_ip, domain, tags, metadata) for the correlation asset types. tags
// carries the k8s workload labels deploys_to matches on; account_id is what
// GCPImpersonation groups service accounts by to keep a project-level grant
// within its project (omitting it caused the cross-project can_assume mesh).
// argMax over synced_at collapses ReplacingMergeTree duplicates without FINAL.
//
// The type filter is a WHERE, not a HAVING: type is immutable per id, so
// filtering rows before the GROUP BY builds aggregation state for only the
// matching assets instead of every row in the table, then discarding most.
// This runs every full correlate and — via LoadViewForTypes — on the partial
// path too, so the difference is large at multi-million-asset scale.
//
// Dead ephemeral resources are excluded (asset.EphemeralLivenessCond). Without
// it correlation derives edges from corpses — a rule cannot tell the
// difference between a live asset row and a deleted one, so the filter
// belongs here, at the one place every rule's input comes from.
//
// metadata is projected to metadataProjectedKeys rather
// than selected whole — see projectMetadataExpr. Annotation producers publish
// only their owned field intents; no projected row is written back over the
// collector's complete observation.
const loadView = `SELECT id,
	argMax(name, synced_at), argMax(type, synced_at), argMax(account_id, synced_at),
	argMax(public_ip, synced_at), argMax(private_ip, synced_at), argMax(domain, synced_at), argMax(tags, synced_at),
	` + projectMetadataExpr + `
	FROM asset_versions_with_derivations
	WHERE type IN (%s) AND ` + asset.EphemeralLivenessCond + `
	GROUP BY id
	LIMIT ?`

// loadByIDs selects specific assets by ID for partial correlate seed.
// Uses the same minimal columns (and the same metadata projection) as
// loadView so the same scan helper applies. id is the GROUP BY key, so
// filtering it in WHERE prunes on the primary key and aggregates only the
// requested ids — not the whole table (this runs on every connector sync via
// PartialCorrelate).
const loadByIDs = `SELECT id,
	argMax(name, synced_at), argMax(type, synced_at), argMax(account_id, synced_at),
	argMax(public_ip, synced_at), argMax(private_ip, synced_at), argMax(domain, synced_at), argMax(tags, synced_at),
	` + projectMetadataExpr + `
	FROM asset_versions_with_derivations
	WHERE id IN (%s)
	GROUP BY id`

// metadataKeyPlaceholders/metadataKeyArgs are metadataProjectedKeys pre-built
// into a CHIn clause once at package init — every loadView/loadByIDs call
// uses the identical fixed key list, so there is no reason to rebuild it on
// every sweep and every PartialCorrelate call.
var metadataKeyPlaceholders, metadataKeyArgs = dbutil.CHIn(metadataProjectedKeys)

// CHRepo reads the correlation view from ClickHouse.
type CHRepo struct {
	ch *db.CH
}

func NewCHRepo(ch *db.CH) *CHRepo { return &CHRepo{ch: ch} }

// loadViewSpillBytes makes the correlation aggregation spill to disk instead of
// dying. loadView is a GROUP BY id over hundreds of thousands of assets whose
// argMax state carries `metadata` (a JSON String) and can peak in the low
// GiBs — not because that's over the server's memory cap alone, but because it
// runs concurrently with the findings pages and their own cache floor.
//
// Spilling is the right trade here: this is a once-per-sweep bulk read with a
// generous timeout, and ClickHouse's temp space is on the data disk with ample
// headroom, so a few GiB of merge-sort spill is free. A retryable kill costs a
// whole correlate sweep; extra seconds cost nothing.
//
// It bounds the aggregation, NOT the result: scanAssets still materialises every
// row in the worker's heap, which is what correlationLimit is for.
const loadViewSpillBytes = 1 << 30 // 1 GiB

func (r *CHRepo) scanAssets(ctx context.Context, query string, args ...any) ([]asset.Asset, error) {
	ctx = r.ch.WithQuerySettings(ctx, map[string]any{
		"max_bytes_before_external_group_by": loadViewSpillBytes,
	})
	var assets []asset.Asset
	err := r.ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				a        asset.Asset
				metaJSON string
			)
			// name is REQUIRED: rules match on it (DeploysTo's compute-service
			// lookup among them), and an empty Name silently kills them.
			// The `if name != ""` guard in NewGraph's computeServiceByName is
			// load-bearing and must stay: an empty key would make every compute
			// service match reposByName[""].
			//
			// account_id is REQUIRED here even though the view is otherwise minimal:
			// GCPImpersonation groups service accounts by AccountID to keep a
			// project-level impersonation grant within its project. Dropping it
			// collapses every SA into the "" bucket and fans impersonation out
			// across ALL projects. See gcp_impersonation.go.
			if err := rows.Scan(&a.ID, &a.Name, &a.Type, &a.AccountID, &a.PublicIP, &a.PrivateIP, &a.Domain, &a.Tags, &metaJSON); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			a.Metadata = decodeMeta(metaJSON)
			assets = append(assets, a)
		}
		return nil
	}, query, args...)
	return assets, err
}

// LoadView returns the correlation-relevant assets (partial: only the fields
// rules match on are populated). The bool reports whether the result hit the
// limit; both callers must treat that as ErrViewTruncated, not as a warning —
// see correlationLimit.
func (r *CHRepo) LoadView(ctx context.Context) ([]asset.Asset, bool, error) {
	qCtx, cancel := context.WithTimeout(ctx, loadViewTimeout)
	defer cancel()

	placeholders, typeArgs := dbutil.CHIn(correlationTypes)
	query := fmt.Sprintf(loadView, metadataKeyPlaceholders, placeholders)
	args := append(append(append([]any{}, metadataKeyArgs...), typeArgs...), correlationLimit)

	assets, err := r.scanAssets(qCtx, query, args...)
	if err != nil {
		return nil, false, fmt.Errorf("LoadView: %w", err)
	}
	return assets, len(assets) >= correlationLimit, nil
}

// LoadViewForTypes is LoadView scoped to a caller-supplied type list — used by
// PartialCorrelate to load only the asset types relevant to changed assets.
func (r *CHRepo) LoadViewForTypes(ctx context.Context, types []string) ([]asset.Asset, bool, error) {
	if len(types) == 0 {
		return nil, false, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, loadViewTimeout)
	defer cancel()

	placeholders, typeArgs := dbutil.CHIn(types)
	query := fmt.Sprintf(loadView, metadataKeyPlaceholders, placeholders)
	args := append(append(append([]any{}, metadataKeyArgs...), typeArgs...), correlationLimit)

	assets, err := r.scanAssets(qCtx, query, args...)
	if err != nil {
		return nil, false, fmt.Errorf("LoadViewForTypes: %w", err)
	}
	return assets, len(assets) >= correlationLimit, nil
}

// LoadByIDs fetches specific assets by ID for the partial correlate seed load.
func (r *CHRepo) LoadByIDs(ctx context.Context, ids []string) ([]asset.Asset, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	placeholders, idArgs := dbutil.CHIn(ids)
	query := fmt.Sprintf(loadByIDs, metadataKeyPlaceholders, placeholders)
	args := append(append([]any{}, metadataKeyArgs...), idArgs...)

	assets, err := r.scanAssets(qCtx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("LoadByIDs: %w", err)
	}
	return assets, nil
}

func decodeMeta(s string) map[string]string {
	if s == "" || s == "{}" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	return m
}
