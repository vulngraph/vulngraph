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
// Matching fields are projected before latest-row aggregation. The breaker
// still refuses an incomplete graph at 600,000 relevant assets.
const loadView = loadViewSource + ` LIMIT ?` + loadViewSettings

// Seeds activate rules and account-scoped invalidations only. Matching fields
// come from the later complete view, so large batches do not retain policy maps.
const loadByIDs = `SELECT id, argMax(type, synced_at), argMax(account_id, synced_at)
 FROM assets WHERE id IN (%s) GROUP BY id`

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

// Projected latest-row aggregation spills before exhausting the shared server
// budget. Temporary IO and client result retention remain measured costs; this
// threshold does not replace the unchanged result-count circuit breaker.
const loadViewSpillBytes = 128 << 20 // 128 MiB; measured with the projected tuple

func (r *CHRepo) scanAssets(ctx context.Context, query string, args ...any) ([]asset.Asset, error) {
	ctx = r.ch.WithQuerySettings(ctx, map[string]any{
		"max_bytes_before_external_group_by": loadViewSpillBytes,
	})
	var assets []asset.Asset
	err := r.ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			a, err := scanCorrelationAsset(rows)
			if err != nil {
				return err
			}
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

// LoadByIDs loads activation fields in bounded SQL requests. Seed pages are
// not one snapshot; the later complete view supplies all matching observations.
func (r *CHRepo) LoadByIDs(ctx context.Context, ids []string) ([]asset.Asset, error) {
	var out []asset.Asset
	for len(ids) > 0 {
		n := 0
		bytes := 0
		for n < len(ids) && n < 200 {
			cost := 6*len(ids[n]) + 3
			if cost > 128<<10 {
				return nil, fmt.Errorf("LoadByIDs: ID exceeds seed query byte limit")
			}
			if bytes+cost > 128<<10 {
				break
			}
			bytes += cost
			n++
		}
		rows, err := r.loadSeedPage(ctx, ids[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
		ids = ids[n:]
	}
	return out, nil
}

func (r *CHRepo) loadSeedPage(ctx context.Context, ids []string) ([]asset.Asset, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	placeholders, args := dbutil.CHIn(ids)

	var out []asset.Asset
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var a asset.Asset
			if err := rows.Scan(&a.ID, &a.Type, &a.AccountID); err != nil {
				return fmt.Errorf("LoadByIDs scan: %w", err)
			}
			out = append(out, a)
		}
		return rows.Err()
	}, fmt.Sprintf(loadByIDs, placeholders), args...)
	if err != nil {
		return nil, fmt.Errorf("LoadByIDs: %w", err)
	}
	return out, nil
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

func scanCorrelationAsset(rows driver.Rows) (asset.Asset, error) {
	var a asset.Asset
	var metaJSON string
	// Name and AccountID are matching inputs, not display-only columns.
	if err := rows.Scan(&a.ID, &a.Name, &a.Type, &a.AccountID, &a.PublicIP, &a.PrivateIP, &a.Domain, &a.Tags, &metaJSON); err != nil {
		return a, fmt.Errorf("scan correlation asset: %w", err)
	}
	a.Metadata = decodeMeta(metaJSON)
	return a, nil
}
