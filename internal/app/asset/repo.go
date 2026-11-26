package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Query strings are package consts named for what they fetch (CLAUDE.md).
const (
	insertAssets = `INSERT INTO assets
		(id, name, type, provider, region, account_id, endpoint, public_ip,
		 private_ip, domain, tags, metadata, risk_score, discovered_at, first_discovered_at, last_seen, synced_at)`

	insertEdges = `INSERT INTO graph_edges
		(src_id, src_type, dst_id, dst_type, edge_type, properties, synced_at)`

	insertChangeLog = `INSERT INTO asset_change_log
		(asset_id, field, old_value, new_value, connector_id)`

	// selectChangeLog reads an asset's field-change history, newest first.
	selectChangeLog = `SELECT asset_id, field, old_value, new_value, connector_id, changed_at
		FROM asset_change_log WHERE asset_id = ? ORDER BY changed_at DESC LIMIT ?`

	// assetArgMaxSelect is the id-lookup form of the asset row select. assets is
	// ORDER BY (type, id), so id-only lookups can't use the
	// primary key; the idx_id bloom index prunes to the few granules holding the id
	// instead of a full-table scan. argMax(col, synced_at) GROUP BY id collapses
	// ReplacingMergeTree versions for those ids — identical to FINAL for a fixed
	// key set, but skip indexes don't apply under FINAL, so FINAL here would mean
	// a full-table scan per lookup. Column order matches scanAsset.
	//
	// The two lifecycle timestamps deliberately do NOT use argMax. They are
	// monotonic facts about the whole row history, not "the newest row's
	// opinion": discovered_at is the FIRST time we ever saw the resource (min)
	// and last_seen the LAST (max). Collectors stamp discovered_at with the
	// sweep's clock, so argMax(discovered_at, synced_at) would return "now" for
	// every asset that had ever been rewritten.
	//
	// min(discovered_at) alone is not durable either: that min is only over
	// SURVIVING ReplacingMergeTree versions, and degrades once old versions
	// merge away. first_discovered_at is what makes it durable — an immutable
	// column pinned at the Service.Ingest layer via earliest(), read here the
	// same way finding/repo.go reads first_detected_at: minIf over nonzero
	// surviving versions, which recovers the true value for ids whose versions
	// haven't collapsed yet and degrades no worse than the column's own
	// guarantee otherwise.
	firstDiscoveredAtAgg = `minIf(first_discovered_at, first_discovered_at > toDateTime(0))`

	assetArgMaxSelect = `SELECT id,
		argMax(name, synced_at), argMax(type, synced_at), argMax(provider, synced_at),
		argMax(region, synced_at), argMax(account_id, synced_at), argMax(endpoint, synced_at),
		argMax(public_ip, synced_at), argMax(private_ip, synced_at), argMax(domain, synced_at),
		argMax(tags, synced_at), argMax(metadata, synced_at), argMax(risk_score, synced_at),
		min(discovered_at), ` + firstDiscoveredAtAgg + `, max(last_seen)
		FROM assets`

	// selectAsset reads the current row for one id.
	selectAsset = assetArgMaxSelect + ` WHERE id = ? GROUP BY id`

	// selectAssetByName reads every current row with an exact name match,
	// newest first — an equality predicate, never a substring scan. See
	// FindByExactName's doc comment for why this exists as its own query
	// instead of routing through the free-text Search filter.
	selectAssetByName = assetArgMaxSelect + ` WHERE name = ? GROUP BY id ORDER BY max(last_seen) DESC LIMIT ?`

	// assetSelect uses FINAL to read the deduplicated ReplacingMergeTree
	// directly. List applies WHERE filters to it (including an id IN subquery
	// for the exposed filter), which is the filtered-FINAL shape CLAUDE.md
	// says to avoid on assets; moving those paths to key-select then ByIDs is
	// not done yet.
	//
	// It relies on background merges keeping duplication low, plus a daily
	// OPTIMIZE job (internal/jobs/optimize.go) that also covers `assets` once
	// its old proj_by_last_seen projection is gone (skipReasonFor refuses to
	// optimize while that projection is live, since the merge would have to
	// rebuild it too — see optimize.go).
	//
	// Do not read the job as a guarantee. Every table it touches is unpartitioned,
	// so each pass is a full-table rewrite; it runs daily, per-table time-bounded,
	// and skips anything above the size guard. Duplication here is bounded by
	// background merges first and that daily pass second. If that ever stops being
	// enough, the fix is a smaller sort key or a partition key, not a faster
	// rewrite treadmill.
	assetSelect = `SELECT id, name, type, provider, region, account_id, endpoint,
		public_ip, private_ip, domain, tags, metadata, risk_score, discovered_at, first_discovered_at, last_seen
		FROM assets FINAL`

	// assetSummary and the List query are NOT here: both apply inventoryReadCond,
	// which is built from quotedCSV at init, so they are vars (see below).

	// externalAssetIDs/assetIDsByType select only the ids matching a filtered
	// predicate, then ListExternal/ListByType hydrate the full row via ByIDs
	// (assetArgMaxSelect ... WHERE id IN (...)). This is the same "select the
	// page's keys with only the columns it filters and sorts on, then hydrate
	// by id" split CLAUDE.md prescribes: public_ip/domain/type have no skip
	// index, so a FINAL WHERE on them forces a full unindexed dedup-merge scan
	// of the whole assets table. A GROUP BY ... HAVING still builds per-id
	// aggregation state for every row (LIMIT/OFFSET cannot prune before HAVING
	// evaluates), but aggregating only public_ip/domain/type/last_seen per id
	// is far cheaper than argMax-ing every column including tags/metadata.
	externalAssetIDs = `SELECT id FROM assets
		GROUP BY id
		HAVING argMax(public_ip, synced_at) != '' OR argMax(domain, synced_at) != ''
		ORDER BY max(last_seen) DESC LIMIT ?`

	assetIDsByType = `SELECT id FROM assets
		GROUP BY id
		HAVING argMax(type, synced_at) = ?
		ORDER BY max(last_seen) DESC LIMIT ?`

	// outgoingEdges fetches edges whose source is any of the given asset IDs —
	// one frontier hop of the blast-radius traversal. The IN list is built with
	// db.CHIn (%s is filled with "?, ?, …", never user data).
	outgoingEdges = `SELECT src_id, src_type, dst_id, dst_type, edge_type, argMax(properties, synced_at)
		FROM graph_edges WHERE src_id IN (%s) AND ` + graphschema.EdgeFreshnessCond + `
		GROUP BY src_id, src_type, dst_id, dst_type, edge_type`

	// incomingEdges is the mirror of outgoingEdges: edges whose destination is any
	// of the given IDs — one hop of a reverse blast-radius ("who can reach X?").
	incomingEdges = `SELECT src_id, src_type, dst_id, dst_type, edge_type, argMax(properties, synced_at)
		FROM graph_edges WHERE dst_id IN (%s) AND ` + graphschema.EdgeFreshnessCond + `
		GROUP BY src_id, src_type, dst_id, dst_type, edge_type`

	// incomingEdgesByType fetches edges of one type pointing AT a destination
	// asset — the lineage lookup (e.g. which repo deploys_to this workload),
	// which the blast-radius walk (outgoing only) never surfaces.
	incomingEdgesByType = `SELECT src_id, src_type, dst_id, dst_type, edge_type, argMax(properties, synced_at)
		FROM graph_edges WHERE dst_id = ? AND edge_type = ? AND ` + graphschema.EdgeFreshnessCond + `
		GROUP BY src_id, src_type, dst_id, dst_type, edge_type`

	// outgoingEdgesByType is the mirror: edges of one type FROM a source asset.
	// Used for typed identity-chain and supply-chain lookups (executes_as,
	// has_role, deploys_to) where fetching all outgoing edges and filtering in Go
	// would over-fetch on high-connectivity assets.
	outgoingEdgesByType = `SELECT src_id, src_type, dst_id, dst_type, edge_type, argMax(properties, synced_at)
		FROM graph_edges WHERE src_id = ? AND edge_type = ? AND ` + graphschema.EdgeFreshnessCond + `
		GROUP BY src_id, src_type, dst_id, dst_type, edge_type`

	// hasExposedEdge is a fast point check: does this asset have an outgoing
	// CONFIRMED exposed_to_internet edge? Used by the enrichment fingerprint so
	// that topology changes re-score without relying solely on the time-based
	// backstop, and as the adjudicator's independent exposure witness.
	//
	// The tier filter mirrors streamNodeRows' `exposed` map exactly: correlate
	// also emits the edge for the `possible` tier so the reach BFS can seed one
	// hop in, and without this predicate the Ladybug path (tier-aware) and this
	// ClickHouse fallback (tier-blind) would answer "is this exposed?" two
	// different ways for the same asset.
	hasExposedEdge = `SELECT count() FROM graph_edges WHERE src_id = ? AND edge_type = 'exposed_to_internet'` +
		` AND JSONExtractString(properties, '` + EdgePropPublicAccess + `') != '` + PublicAccessPossible + `' AND ` + graphschema.EdgeFreshnessCond

	// existingAssetIDs returns the subset of the given ids that currently have an
	// asset row. GROUP BY id (no FINAL, no argMax of other columns — presence is
	// all the caller needs) collapses ReplacingMergeTree versions the same way
	// ByIDs/selectAsset do, so it shares their idx_id bloom-index-pruned shape
	// instead of an ad hoc DISTINCT form that would defeat that pruning. Used by
	// the dangling-finding sweep to tell a finding whose resource still
	// exists from one whose resource is gone. %s is filled by db.CHIn — never
	// user data.
	existingAssetIDs = `SELECT id FROM assets WHERE id IN (%s) GROUP BY id`

	// providerHighWater returns the most recent last_seen across a provider's
	// assets — i.e. when that provider last successfully collected ANYTHING.
	//
	// This is the fail-safe reference point for deciding an asset is gone. Asset
	// rows are never deleted from this ReplacingMergeTree, so "the row exists"
	// (existingAssetIDs) cannot distinguish a live resource from one that vanished
	// months ago; only last_seen can. But comparing last_seen against wall-clock
	// time would mass-resolve the entire estate the moment a collector breaks —
	// everything would look stale at once. Anchoring to the provider's own
	// high-water mark prevents that for a provider-wide outage: the mark stops
	// advancing, the cutoff stops moving, and nothing new is judged gone. It is
	// one mark per provider, not per connector, so one broken connector among
	// several healthy ones of the same provider is not protected.
	providerHighWater = `SELECT max(last_seen) FROM assets WHERE provider = ?`
)

// Bulk-sync row ceilings. When a ForSync load reaches one of these, it was
// truncated, and the result says so (AssetSyncResult.Truncated,
// EdgeSyncResult.TruncatedTypes) so the graph build treats its coverage as
// incomplete rather than full (CLAUDE.md: Degraded input).
const (
	syncAssetLimit = 5000000
	// syncBulkEdgeLimit caps only the high-volume context edges (connected_via_sg,
	// depends_on, dns_points_to etc.). Attack-path critical edges (exposed_to_internet,
	// executes_as, can_assume, federated_access, …) are loaded with NO limit in a
	// separate query so they ALWAYS appear in the graph regardless of SG/SBOM volume.
	// Sized as a runaway guard, not a cap meant to bind in normal operation — a cap
	// that regularly binds is indistinguishable from a healthy build without reading
	// a gauge, which defeats the point of having an explicit ceiling at all.
	syncBulkEdgeLimit = 750000
	// syncBulkPerTypeLimit caps each bulk edge_type individually (LIMIT n BY
	// edge_type) so one high-volume type (SBOM depends_on, dns_points_to)
	// cannot starve every other bulk type out of the shared total limit.
	//
	// The per-type cap needs headroom over the real current volume of the
	// biggest bulk type, whichever that currently is — raise it when that
	// type's real volume grows past it. Truncation here is deterministic
	// (bulkEdgesQ's ORDER BY), so a cap that binds always drops the SAME
	// alphabetically-late edges on every build rather than flapping.
	// graph_ladybug_edge_cap_hit is the gauge that catches this if it starts
	// binding; the GraphLadybugEdgeCapHit alert fires on it.
	//
	// The better long-term fix for a type whose real volume keeps growing
	// (e.g. depends_on) is gating its emission to assets that actually carry
	// findings, not raising this cap indefinitely — the same reasoning that
	// keeps signal-free dns_record nodes out of the graph (asset_filter.go).
	// This must stay a cap, not a SQL filter here: scoping the edges to, say,
	// vulnerable packages would silently narrow Ladybug/Cypher consumers that
	// need the FULL dependency graph, replacing an observable cap with an
	// unobservable filter.
	syncBulkPerTypeLimit = 500000
)

// SyncEdgeTypes is the union of criticalEdgeTypes and bulkEdgeTypes — every
// edge_type value loaded into Ladybug for bulk sync. Every entry MUST have a
// rel-table mapping in graphstore.edgeTypeToRel AND an UNWIND template in
// graphstore.edgeUnwindQ, or it is silently dropped at insert time —
// graphstore's TestSyncEdgeTypesAreMapped enforces this so the two allowlists
// can never drift apart. These are real edge_type values, not correlation
// rule names (e.g. the internet_reachability rule emits exposed_to_internet).
//
// Filtering in SQL keeps low-value collector edges out of Go memory entirely.
// Split into criticalEdgeTypes (no limit) and bulkEdgeTypes (syncBulkEdgeLimit
// cap) below.
var SyncEdgeTypes = append(criticalEdgeTypes, bulkEdgeTypes...)

// NeverSyncTypes are asset types excluded from Ladybug bulk sync at the SQL level.
// These are pure infrastructure topology — they appear in ClickHouse but are
// never referenced in a security Cypher query and their absence does not break
// any traversal path. Filtering in SQL means they never load into Go heap,
// preventing the OOM spike during Ladybug rebuild. Must stay in sync with
// graphstore.neverKeepTypes.
// EphemeralLivenessCond keeps DEAD ephemeral resources out of the graph. Asset
// rows are never deleted from the ReplacingMergeTree — they simply stop being
// refreshed (liveness is last_seen, not row presence) — and for a resource
// that is recreated on every deploy, the accumulated rows are corpses, not
// inventory. Without this gate, correlate happily recomputes edges for a
// pod deleted weeks ago, and a traversal from that stale exposure edge
// dead-ends since its containment edges have correctly aged out.
//
// The cutoff is anchored to the k8s_pod type's high-water mark across ALL
// clusters, never wall-clock: if every k8s collector breaks, the high-water
// freezes and nothing is dropped. The mark is not per cluster, so with several
// clusters one healthy cluster keeps it moving, and a broken cluster's pods,
// containers and jobs ARE judged dead after the 72h grace. 'container' is
// gated on the same k8s_pod mark whatever its provider, including AWS ECS
// containers.
//
// Not applied to cloud resource types other than 'container': most stale
// cloud rows are victims of slow or broken collection rather than deletion, so
// filtering them the same way would delete most of the graph. An EC2 instance that stopped
// being collected may well still exist; a pod that stopped being collected
// does not. Only add a type here when absence genuinely means the resource is
// gone.
//
// The inner table is ALIASED, and that alias is load-bearing. Unqualified, the
// subquery's `WHERE type = 'k8s_pod'` binds to whatever `type` is in scope at
// the point the condition is applied — and several callers apply it over a
// projection that also exposes a `type` column, which would make the
// high-water lookup filter on the OUTER row instead of the assets table it
// names, matching nothing for every non-pod row. Qualifying the subquery
// fixes every reader at once, which is why the condition is a single shared
// const. TestCHRepo_LiveIDsAppliesEphemeralLiveness pins it.
//
// 'container' and 'k8s_job' are included alongside 'k8s_pod' because a
// Kubernetes container's or job's lifecycle is tied to its pod's: a corpse,
// not inventory, once its pod is gone. ECS containers share the 'container'
// type and so share the k8s_pod-anchored gate described above. gce_instance is deliberately
// NOT added: it is a cloud resource type (the class this cond explicitly
// excludes above), and a stale gce_instance row is still often
// status=RUNNING at last observation — the "victim of broken collection, not
// deletion" case this mechanism must never touch.
const EphemeralLivenessCond = `(type NOT IN ('k8s_pod', 'container', 'k8s_job') OR last_seen > (
	SELECT max(hw.last_seen) FROM assets AS hw WHERE hw.type = 'k8s_pod'
) - INTERVAL 72 HOUR)`

var NeverSyncTypes = []string{
	"package",
	"ebs_volume", "vpc",
	// subnet is deliberately NOT here: it feeds InSubnet edge correlation and
	// has its own Subnet node table in graphstore.schemaDDL.
	//
	// sqs_queue, sns_topic, kms_key and ecr_repository are deliberately NOT here
	// even though they sit in this pure-topology group: each carries a
	// resource-policy exposure check whose public_access key is a real
	// observation, and excluding the type from Ladybug would mean it could never
	// reach an internet_hops value under any circumstance — worse than merely
	// unreachable. All four fall back to the generic NodeAsset label, the SAFE
	// default when no typed rel table exists for a type.
	"vpc_peering_connection", "gcp_firewall",
	// elastic_ip is deliberately NOT here either. An Elastic IP is not
	// topology — it is a public IP address, i.e. attack surface, and the single
	// most common thing a DNS record resolves to. Excluding it at the SQL level
	// would keep the asset from reaching filterLadybugAssets, so every
	// dns_points_to edge landing on one would be silently discarded, and the
	// dns_chain_exposure named query would lose most of its input.
	"nat_gateway", "ecs_cluster", "k8s_namespace",
	"k8s_configmap", "k8s_persistentvolumeclaim", "k8s_persistentvolume",
	"cloudtrail_trail", "cloudwatch_log_group", "cloudwatch_alarm",
	"route_table", "network_interface", "internet_gateway",
	"gcp_network", "gcp_subnetwork", "gcp_router",
	"azure_network_security_group", "azure_virtual_network", "azure_subnet",
	// The declared_* entries below are all IaC correlation intermediates: each
	// is read by one correlate rule, joined to the live asset it describes,
	// then never needed again — none of them must become a Ladybug Asset node.
	// declared_k8s_workload: correlate LoadView, joined to live k8s assets.
	"declared_k8s_workload",
	// declared_ci_access: the ci_access rule, joined to live iam_role/gcp_service_account.
	"declared_ci_access",
	// declared_tf_resource: the tf_ownership rule, joined to a live asset by arn/id.
	"declared_tf_resource",
	// declared_cloud_identity and declared_image_build: the GitHub
	// identity-harvest and image-harvest intermediates, joined to live
	// iam_role/iam_user/gcp_service_account and container_image assets by the
	// declared_identity_ownership and image_ownership rules. correlate loads
	// them through its own query (correlate.correlationTypes), never through
	// the Ladybug sync, so excluding them here cannot starve either rule.
	"declared_cloud_identity",
	"declared_image_build",
	// aws_scp_set carries an account's Service Control Policies: read by
	// CIEM at analysis time to cap effective permissions, never traversed in a
	// Cypher query — it must not become a Ladybug Asset node.
	"aws_scp_set",
}

// NonInventoryTypes are asset rows that are NOT resources. Every entry is an
// Infrastructure-as-Code DECLARATION — a parsed line of YAML/Terraform/workflow
// text out of a git repo — written into the assets table only because the correlate
// LoadView needs it as a join input. The resource each one describes is
// collected separately, by the cloud connector that owns it, under its own id.
//
// So counting them as inventory is a category error twice over: it invents
// resources that do not exist, AND it double-counts the real resource each
// declaration points at. They carry no provider because they do not come
// from one.
//
// This is a SUPERSET of the declared_* entries in NeverSyncTypes: correlate
// reads every one of them through its OWN load query
// (correlate.correlationTypes), never through the Ladybug sync, so excluding
// them from the graph cannot starve the rules that consume them.
//
// It is NOT a subset relationship in the other direction, and must not become
// one: NeverSyncTypes also holds real resources (ebs_volume, vpc, nat_gateway)
// that are pure graph-topology noise but are unquestionably inventory. Those are
// counted. Excluding a live resource from inventory hides risk; this list is
// only ever for rows that describe a resource rather than being one.
//
// aws_scp_set is deliberately NOT here even though it is also "read by
// correlate, never traversed": an SCP set is a real, live AWS configuration
// object attached to an account, not a parse of a file in a repo.
var NonInventoryTypes = []string{
	"declared_ci_access",
	"declared_cloud_identity",
	"declared_image_build",
	"declared_k8s_workload",
	"declared_tf_resource",
}

// nonInventorySet is NonInventoryTypes as a set, for the one UI-facing read that
// cannot express the exclusion in SQL (the risk view ranks ids supplied by the
// finding store). Derived from the slice so the two can never drift.
var nonInventorySet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(NonInventoryTypes))
	for _, t := range NonInventoryTypes {
		m[t] = struct{}{}
	}
	return m
}()

// isNonInventoryType reports whether a type is an IaC declaration rather than a
// resource — the Go-side twin of inventoryReadCond's type exclusion.
func isNonInventoryType(t string) bool {
	_, ok := nonInventorySet[t]
	return ok
}

// inventoryReadCond is the predicate EVERY UI-facing inventory read applies:
// live resources only (EphemeralLivenessCond) and real resources only
// (NonInventoryTypes). One shared string so the Assets page's total, its
// provider/type breakdown and its rows can never answer "what do we own?" three
// different ways — the same single-definition discipline
// graphschema.EdgeFreshnessCond enforces for edges. Asset rows are never
// deleted (liveness is last_seen, not row presence), so an ungated read of a
// ReplacingMergeTree reports every corpse ever collected as if it still exists.
//
// The gated count is still expected to run well above the graph's own node
// count: the graph additionally drops NeverSyncTypes and edge-gates
// dns_record, neither of which is evidence a resource is gone. ec2_instance in
// particular is NOT gated here and must not be — it is a cloud resource type,
// the class EphemeralLivenessCond explicitly excludes because a stale cloud
// row is far more often a victim of broken collection than a deletion, and
// liveness_test.go pins ec2_instance out of that condition.
//
// The predicate is applied where `type` and `last_seen` are the assets table's
// own columns, never over a projection that re-exposes those names — see
// EphemeralLivenessCond's comment and liveAssetIDs for why that matters.
var inventoryReadCond = EphemeralLivenessCond +
	` AND type NOT IN (` + quotedCSV(NonInventoryTypes) + `)`

// InventoryReadCond exports inventoryReadCond for the rare cross-domain raw
// `assets` read outside this package (e.g. finding.costAtRiskFrom's join to
// cost-bearing asset rows) — a plain string constant, not this package's repo
// type, so importing it does not reach into asset's repo (CLAUDE.md
// layering). Prefer a real service-interface call where one exists; this
// exists because the callers compose a single raw SQL string that has to
// embed the predicate as text, not invoke a Go method.
var InventoryReadCond = inventoryReadCond

// assetSummary is the inventory breakdown behind the Assets page: one exact
// total, one count per provider, one count per type — from a single pass over
// the gated table.
//
// uniqExact(id), NOT count(). The table is ORDER BY (type, id), so its
// ReplacingMergeTree dedup key is that TUPLE rather than the id: two rows for
// the same asset id that disagree on type are, to FINAL, two different assets.
// provider is deliberately not in the sort key, which closes the one fork seen
// in practice (a package discovered both inside a container image and in a
// GitHub SBOM, under two providers); uniqExact(id) keeps the READS honest
// against any type fork.
//
// GROUPING SETS gives all three aggregations in one scan and makes each one
// EXACT, which summing a (provider, type) grid in Go cannot do: a dual-provider
// asset is one asset in the total and one asset in its by_type bucket, while
// genuinely appearing under both providers (so by_provider figures can sum to
// more than the total — the honest answer to "how many assets does this
// provider have?" for each). grouping(col) returns 0 when col is part of the
// current grouping set and 1 when it has been aggregated away; Summary() fails
// loudly on any other flag combination rather than silently attributing a row
// to the wrong bucket.
var assetSummary = `SELECT provider, type, uniqExact(id) AS n,
		grouping(provider) AS gp, grouping(type) AS gt
	FROM assets FINAL
	WHERE ` + inventoryReadCond + `
	GROUP BY GROUPING SETS ((provider), (type), ())`

// listAllForSyncQ fetches every current asset for Ladybug bulk sync, excluding
// NeverSyncTypes at the SQL level so they never load into Go heap. Unlike List()
// it does NOT apply assetPageLimit — the page cap (100) is for the web UI and
// must never silently truncate a bulk load.
// Dead ephemeral resources are excluded here too (EphemeralLivenessCond): otherwise a
// very large number of dead pods would load into the Go heap and then into Ladybug on
// every rebuild, which matters for a memory-bounded worker, and they are nodes no
// traversal should reach.
var listAllForSyncQ = fmt.Sprintf("%s WHERE type NOT IN (%s) AND %s ORDER BY id LIMIT %d",
	assetSelect, quotedCSV(NeverSyncTypes), EphemeralLivenessCond, syncAssetLimit)

// Attack-path critical edge types — loaded with NO limit so they always appear in
// the graph regardless of bulk edge volume. Tier membership is declared in the
// internal/graphschema registry (single source of truth).
//
// connected_via_sg (asset→SecurityGroup spoke-hub) powers the lateral-movement
// queries. It lives in the critical (uncapped) tier ON PURPOSE: the bulk tier
// shares one combined LIMIT that can already run at or over cap, so a bulk
// entry would be truncated arbitrarily and the queries could silently get
// nothing. criticalEdgesQ's dst_id guard keeps only memberships whose
// destination is a real security group, at fetch.
//
// contains_data is intentionally NOT critical: loading it uncapped in the
// memory-heavy GROUP BY argMax pushed ClickHouse past its memory limit,
// wedging the whole Ladybug rebuild. DSPM edges stay in the bulk tier.
var criticalEdgeTypes = graphschema.TierEdgeTypes(graphschema.TierCritical)

// Bulk edge types — high-volume topology / SBOM edges loaded after critical edges,
// capped at syncBulkEdgeLimit (a SINGLE combined LIMIT across all types, with no
// ORDER BY). Adding a new type here risks starving existing bulk types out of
// the shared cap; put security-relevant edges in the critical tier (uncapped)
// instead. Declared in internal/graphschema.
var bulkEdgeTypes = graphschema.TierEdgeTypes(graphschema.TierBulk)

// criticalEdgesQ loads all attack-path critical edges with NO LIMIT.
// These are small in count but essential — every attack-path Cypher query uses them.
// No ORDER BY: Ladybug doesn't need ordered edges, and sorting the full set before
// returning would be pure memory pressure. max_bytes_before_external_group_by
// spills the GROUP BY/argMax to disk instead of OOMing ClickHouse once the
// critical-edge set grows.
//
// connected_via_sg is the one uncapped edge that could be huge. The dst_id
// filter below only fetches memberships whose destination is a real
// security_group asset, so a malformed row (one pointing at an instance ID,
// say) is never read into Go heap — ReplacingMergeTree would otherwise keep
// such rows until TTL. The correlator emits only security-group destinations;
// the filter is belt-and-braces.
var criticalEdgesQ = fmt.Sprintf(
	`SELECT src_id, src_type, dst_id, dst_type, edge_type, argMax(properties, synced_at)
		FROM graph_edges WHERE edge_type IN (%s)
		  AND `+graphschema.EdgeFreshnessCond+`
		  AND (edge_type != 'connected_via_sg'
		       OR dst_id IN (SELECT id FROM assets WHERE type = 'security_group'))
		GROUP BY src_id, src_type, dst_id, dst_type, edge_type
		SETTINGS max_bytes_before_external_group_by = 2000000000`,
	quotedCSV(criticalEdgeTypes))

// bulkEdgesQ loads high-volume context edges, capped per type AND in total.
// These enrich the graph but their absence never breaks an attack-path query
// (every Reach edge type is critical-tier — the registry enforces it).
//
// ORDER BY makes both caps stable across rebuilds (without it, which rows
// survive the LIMIT depends on storage/merge order and flaps); the
// external-sort SETTING spills the sort to disk so this cannot OOM the way an
// unbounded in-memory sort could.
//
// The determinism cuts both ways, and it is the sharpest edge in this file:
// ordering by edge_type means the total cap starves ALPHABETICALLY-LATE types
// to ZERO rows, identically on every build, rather than thinning everything a
// little. Reach and Inherit types are all critical-tier (uncapped) and a
// registry guard test enforces it, so nothing the internet-hops computation
// consumes can reach this query — anything added to the bulk tier must be
// survivable at zero rows.
var bulkEdgesQ = fmt.Sprintf(
	`SELECT src_id, src_type, dst_id, dst_type, edge_type, argMax(properties, synced_at)
		FROM graph_edges WHERE edge_type IN (%s)
		AND `+graphschema.EdgeFreshnessCond+`
		GROUP BY src_id, src_type, dst_id, dst_type, edge_type
		ORDER BY edge_type, src_id, dst_id
		LIMIT %d BY edge_type
		LIMIT %d
		SETTINGS max_bytes_before_external_group_by = 2000000000,
		         max_bytes_before_external_sort = 2000000000`,
	quotedCSV(bulkEdgeTypes), syncBulkPerTypeLimit, syncBulkEdgeLimit)

// quotedCSV renders a slice of trusted, hard-coded literals as a single-quoted SQL
// list ('a', 'b', …). Only ever called with package-level, hard-coded type lists
// (NonInventoryTypes, NeverSyncTypes, criticalEdgeTypes, bulkEdgeTypes), never
// user input.
func quotedCSV(vals []string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = "'" + v + "'"
	}
	return strings.Join(q, ", ")
}

// CHRepo implements Repo on ClickHouse.
type CHRepo struct {
	ch *db.CH
}

func NewCHRepo(ch *db.CH) *CHRepo { return &CHRepo{ch: ch} }

// assetBatchSize caps each ClickHouse batch insert. One giant batch for a large
// GitHub org (thousands of repos + packages) causes PrepareBatch to timeout.
// 500 rows per batch keeps each insert well under 1s.
const assetBatchSize = 500

// assetWriteBudget is the wall-clock an inventory upsert is guaranteed even when
// the sync job's own deadline is already spent (see db.WithWriteBudget). Sized
// for a large connector: tens of thousands of GitHub assets is under a hundred
// batches, which stays well inside this even while contending for the
// ClickHouse semaphore.
const assetWriteBudget = 5 * time.Minute

func (r *CHRepo) UpsertAssets(ctx context.Context, assets []Asset) error {
	if len(assets) == 0 {
		return nil
	}
	ctx, cancel := db.WithWriteBudget(ctx, assetWriteBudget)
	defer cancel()
	now := time.Now()
	for start := 0; start < len(assets); start += assetBatchSize {
		end := min(start+assetBatchSize, len(assets))
		chunk := assets[start:end]
		err := r.ch.Batch(ctx, insertAssets, func(b driver.Batch) error {
			for _, a := range chunk {
				if err := b.Append(
					a.ID, a.Name, a.Type, string(a.Provider), a.Region, a.AccountID,
					a.Endpoint, a.PublicIP, a.PrivateIP, a.Domain,
					a.Tags, encodeMap(a.Metadata), a.RiskScore, a.DiscoveredAt, firstDiscoveredAt(a), a.LastSeen, now,
				); err != nil {
					return fmt.Errorf("append asset %s: %w", a.ID, err)
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("UpsertAssets: %w", err)
		}
	}
	return nil
}

// WriteChangeLog appends per-field change rows to the audit log. Best-effort:
// the caller logs and continues on error (change history is observability, not
// a correctness-critical write).
func (r *CHRepo) WriteChangeLog(ctx context.Context, connectorID string, changes []FieldChange) error {
	if len(changes) == 0 {
		return nil
	}
	return r.ch.Batch(ctx, insertChangeLog, func(b driver.Batch) error {
		for _, c := range changes {
			if err := b.Append(c.AssetID, c.Field, c.OldValue, c.NewValue, connectorID); err != nil {
				return fmt.Errorf("append change %s/%s: %w", c.AssetID, c.Field, err)
			}
		}
		return nil
	})
}

// ChangeLog returns an asset's field-change history, newest first.
func (r *CHRepo) ChangeLog(ctx context.Context, assetID string, limit int) ([]FieldChange, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []FieldChange
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var c FieldChange
			if err := rows.Scan(&c.AssetID, &c.Field, &c.OldValue, &c.NewValue, &c.ConnectorID, &c.ChangedAt); err != nil {
				return fmt.Errorf("scan change: %w", err)
			}
			out = append(out, c)
		}
		return rows.Err()
	}, selectChangeLog, assetID, limit)
	if err != nil {
		return nil, fmt.Errorf("ChangeLog: %w", err)
	}
	return out, nil
}

func (r *CHRepo) UpsertEdges(ctx context.Context, edges []Edge) error {
	if len(edges) == 0 {
		return nil
	}
	ctx, cancel := db.WithWriteBudget(ctx, assetWriteBudget)
	defer cancel()
	now := time.Now()
	for start := 0; start < len(edges); start += assetBatchSize {
		end := min(start+assetBatchSize, len(edges))
		chunk := edges[start:end]
		err := r.ch.Batch(ctx, insertEdges, func(b driver.Batch) error {
			for _, e := range chunk {
				if err := b.Append(
					e.SrcID, e.SrcType, e.DstID, e.DstType, e.EdgeType, encodeMap(e.Properties), now,
				); err != nil {
					return fmt.Errorf("append edge %s->%s: %w", e.SrcID, e.DstID, err)
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("UpsertEdges: %w", err)
		}
	}
	return nil
}

func (r *CHRepo) GetAsset(ctx context.Context, id string) (Asset, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var (
		found bool
		a     Asset
	)
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			scanned, err := scanAsset(rows)
			if err != nil {
				return err
			}
			a, found = scanned, true
		}
		return nil
	}, selectAsset, id)
	if err != nil {
		return Asset{}, fmt.Errorf("GetAsset: %w", err)
	}
	if !found {
		return Asset{}, ErrNotFound
	}
	return a, nil
}

// FindByExactName returns every asset whose name equals name exactly, newest
// first, bounded by limit. WHERE name = ? is an equality predicate, not a
// substring scan — see resolveCandidates' comment (service.go) for why
// ResolveID needs this instead of the free-text Search fallback: an exact-name
// requirement gains nothing from ILIKE's wildcard cost.
func (r *CHRepo) FindByExactName(ctx context.Context, name string, limit int) ([]Asset, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var out []Asset
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			a, err := scanAsset(rows)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return nil
	}, selectAssetByName, name, limit)
	if err != nil {
		return nil, fmt.Errorf("FindByExactName: %w", err)
	}
	return out, nil
}

// firstDiscoveredAt is the value written to the first_discovered_at column. A
// caller that constructed an Asset without going through Service (a collector
// emitting a brand-new resource, a test, a future source) leaves it zero;
// write that asset's own DiscoveredAt instead, never zero. Writing zero would
// poison the min-over-nonzero read for the rest of the asset's life if the
// nonzero filter were ever dropped, and would mean a genuinely-new asset has
// no recorded first observation at all until something else re-writes it.
// Mirrors finding.firstDetectedAt exactly.
//
// This is a floor, not the pin: pinning an EXISTING asset's value to what is
// already stored is Service.Ingest's job, which knows the prior row. The repo
// cannot — it does not read before it writes.
func firstDiscoveredAt(a Asset) time.Time {
	if a.FirstDiscoveredAt.IsZero() {
		return a.DiscoveredAt
	}
	return a.FirstDiscoveredAt
}

// scanAsset reads one asset row (the 16 columns the asset SELECTs share).
func scanAsset(rows driver.Rows) (Asset, error) {
	return scanAssetKeep(rows, nil, false)
}

// scanAssetKeep is scanAsset with an optional projection: a non-nil keep set narrows
// Metadata to those keys and skips allocating the rest (see decodeMapKeep), and skipTags
// leaves Tags nil. nil/false means "everything", which is what every non-sync reader
// wants. Tags cost significant live heap on a large corpus and the graph reads none of
// them (asset.SyncProjection).
func scanAssetKeep(rows driver.Rows, keep map[string]struct{}, skipTags bool) (Asset, error) {
	var (
		a        Asset
		provider string
		metaJSON string
	)
	if err := rows.Scan(
		&a.ID, &a.Name, &a.Type, &provider, &a.Region, &a.AccountID, &a.Endpoint,
		&a.PublicIP, &a.PrivateIP, &a.Domain, &a.Tags, &metaJSON, &a.RiskScore,
		&a.DiscoveredAt, &a.FirstDiscoveredAt, &a.LastSeen,
	); err != nil {
		return Asset{}, fmt.Errorf("scanAsset: %w", err)
	}
	a.Provider = Provider(provider)
	if skipTags {
		// Scanned above (the column is in the shared SELECT) but not retained:
		// hundreds of bytes of live heap per asset that the graph loader never looks at.
		a.Tags = nil
	}
	if keep == nil {
		a.Metadata = decodeMap(metaJSON)
	} else {
		a.Metadata = decodeMapKeep(metaJSON, keep)
	}
	return a, nil
}

const defaultExternalLimit = 1000

// assetPageLimit caps one List page; the handler emits a next cursor when a
// full page comes back.
const assetPageLimit = 100

// listQuery builds the inventory page SQL and its args. It is separate from List
// so the query text is assertable without a database: listQuery is what
// TestAssetReadersApplyLiveness inspects across every filter combination,
// including the cursor path, where a WHERE-clause mistake produces
// `assets FINAL AND (...)` on every page but the first.
func listQuery(f Filter) (string, []any, error) {
	// Every inventory read starts from the same gate — live resources, real
	// resources (inventoryReadCond). It is FIRST in conds, so the WHERE clause is
	// never empty and the cursor predicate is always an AND.
	conds := []string{inventoryReadCond}
	var args []any
	if f.Provider != "" {
		conds = append(conds, "provider = ?")
		args = append(args, f.Provider)
	}
	if f.Type != "" {
		conds = append(conds, "type = ?")
		args = append(args, f.Type)
	}
	if f.Region != "" {
		conds = append(conds, "region = ?")
		args = append(args, f.Region)
	}
	if f.AccountID != "" {
		conds = append(conds, "account_id = ?")
		args = append(args, f.AccountID)
	}
	if f.Search != "" {
		cond, searchArgs := assetSearchCondition(f.Search)
		conds = append(conds, cond)
		args = append(args, searchArgs...)
	}

	// With FINAL the table is already deduplicated — use WHERE/AND for all filters,
	// no GROUP BY or HAVING needed.
	if f.Exposed {
		conds = append(conds,
			"id IN (SELECT DISTINCT src_id FROM graph_edges WHERE edge_type = 'exposed_to_internet' AND "+graphschema.EdgeFreshnessCond+")")
	}
	if f.MinScore > 0 {
		conds = append(conds, "risk_score >= ?")
		args = append(args, f.MinScore)
	}

	// conds is never empty (inventoryReadCond is always in it), so the WHERE is
	// unconditional — and so is the cursor's AND below.
	query := assetSelect + " WHERE " + strings.Join(conds, " AND ")

	// Keyset cursor: (last_seen DESC, id DESC) — same order as ORDER BY below.
	if f.Cursor != "" {
		ls, id, err := decodeCursor(f.Cursor)
		if err != nil {
			return "", nil, err
		}
		query += " AND (last_seen, id) < (?, ?)"
		args = append(args, ls, id)
	}

	limit := f.Limit
	if limit <= 0 || limit > assetPageLimit {
		limit = assetPageLimit
	}
	query += " ORDER BY last_seen DESC, id DESC LIMIT ?"
	args = append(args, limit)
	return query, args, nil
}

// List returns assets matching the filter, newest first (last_seen, id), with
// keyset pagination via Filter.Cursor. Live, real inventory only — see
// inventoryReadCond.
func (r *CHRepo) List(ctx context.Context, f Filter) ([]Asset, error) {
	qCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Server-side timeout: kills the ClickHouse query if it exceeds 12s,
	// not just the Go-side wait.
	qCtx = r.ch.WithQuerySettings(qCtx, map[string]any{"max_execution_time": 12})

	query, args, err := listQuery(f)
	if err != nil {
		return nil, err
	}

	var assets []Asset
	err = r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			a, err := scanAsset(rows)
			if err != nil {
				return err
			}
			assets = append(assets, a)
		}
		return nil
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	return assets, nil
}

// ListAllForSync returns every current asset without the pagination cap.
// Use this for Ladybug bulk sync — List() is capped at assetPageLimit (100).
//
// proj narrows what is materialised: which Metadata keys to keep, and whether to retain
// Tags at all. The zero value means everything. Passing the wrong metadata set silently
// empties graph columns rather than failing, which is why the caller derives it from a
// registry with a guard test (graphstore.SyncMetadataKeys) instead of hardcoding a list.
// See asset.SyncProjection for the cost of each field.
func (r *CHRepo) ListAllForSync(ctx context.Context, proj SyncProjection) (AssetSyncResult, error) {
	qCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	var keep map[string]struct{}
	if len(proj.MetadataKeys) > 0 {
		keep = make(map[string]struct{}, len(proj.MetadataKeys))
		for _, k := range proj.MetadataKeys {
			keep[k] = struct{}{}
		}
	}
	var assets []Asset
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			a, err := scanAssetKeep(rows, keep, proj.SkipTags)
			if err != nil {
				return err
			}
			assets = append(assets, a)
		}
		return nil
	}, listAllForSyncQ)
	if err != nil {
		return AssetSyncResult{}, fmt.Errorf("ListAllForSync: %w", err)
	}
	res := AssetSyncResult{Assets: assets, Truncated: len(assets) >= syncAssetLimit}
	if res.Truncated {
		log.FromContext(ctx).Warn().Int("limit", syncAssetLimit).
			Msg("asset: ListAllForSync hit row ceiling — Ladybug graph may be missing assets")
	}
	return res, nil
}

// ByIDs returns the current row for each given asset id (argMax collapses
// ReplacingMergeTree versions, never FINAL — see assetArgMaxSelect). Missing
// ids are absent; result order is unspecified (callers that need an order
// impose it themselves).
func (r *CHRepo) ByIDs(ctx context.Context, ids []string) ([]Asset, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	assets, err := r.byIDsCtx(qCtx, ids)
	if err != nil {
		return nil, fmt.Errorf("ByIDs: %w", err)
	}
	return assets, nil
}

// byIDsCtx is ByIDs without imposing its own timeout — for callers (ListExternal,
// ListByType) that already hold a longer-lived context spanning a prior
// id-selection query plus this hydration query.
func (r *CHRepo) byIDsCtx(ctx context.Context, ids []string) ([]Asset, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	placeholders, args := dbutil.CHIn(ids)
	query := assetArgMaxSelect + " WHERE id IN (" + placeholders + ") GROUP BY id"

	var assets []Asset
	err := r.ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			a, err := scanAsset(rows)
			if err != nil {
				return err
			}
			assets = append(assets, a)
		}
		return nil
	}, query, args...)
	return assets, err
}

// orderByIDs reorders hydrated rows to match the id-selection query's order
// (ByIDs/byIDsCtx documents its own result order as unspecified). Ids with no
// matching row (deleted between the selection and hydration queries) are
// dropped rather than padded with a zero-value Asset.
func orderByIDs(ids []string, assets []Asset) []Asset {
	byID := make(map[string]Asset, len(assets))
	for _, a := range assets {
		byID[a.ID] = a
	}
	out := make([]Asset, 0, len(assets))
	for _, id := range ids {
		if a, ok := byID[id]; ok {
			out = append(out, a)
		}
	}
	return out
}

// Summary returns the exact live-inventory total plus counts by provider and by
// type (see assetSummary for the gate, the uniqExact and the GROUPING SETS).
//
// The three figures come back interleaved in one result set, tagged by
// grouping(), rather than being derived from one another in Go — summing a
// (provider, type) grid three ways would let the table's dedup-key fork
// double-count a row in more than one bucket.
//
// An unrecognised flag pair is an ERROR, not a skipped row: this reader's whole
// job is to say how much we own, and quietly dropping a grouping set — or worse,
// filing it under the wrong bucket — would understate the estate with no signal
// at all.
func (r *CHRepo) Summary(ctx context.Context) (Summary, error) {
	qCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	out := Summary{ByProvider: map[string]int{}, ByType: map[string]int{}}
	sawTotal := false
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				provider, typ string
				n, gp, gt     uint64
			)
			if err := rows.Scan(&provider, &typ, &n, &gp, &gt); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			switch {
			case gp == 0 && gt == 1: // grouped by provider only
				out.ByProvider[provider] = int(n)
			case gp == 1 && gt == 0: // grouped by type only
				out.ByType[typ] = int(n)
			case gp == 1 && gt == 1: // the grand total
				out.Total, sawTotal = int(n), true
			default:
				return fmt.Errorf("unexpected grouping flags gp=%d gt=%d: assetSummary's GROUPING SETS and this switch have drifted", gp, gt)
			}
		}
		return rows.Err()
	}, assetSummary)
	if err != nil {
		return Summary{}, fmt.Errorf("Summary: %w", err)
	}
	if !sawTotal {
		// The () grouping set always produces exactly one row, even over an empty
		// table. Its absence means the result was truncated or the query changed
		// shape — either way a zero total would read as "we own nothing".
		return Summary{}, fmt.Errorf("Summary: no grand-total row in result")
	}
	return out, nil
}

// clampExternalLimit is pulled out of ListExternal so its exact behavior —
// nonsensical or over-large caller limits silently fall back to
// defaultExternalLimit rather than erroring — is unit-testable without
// ClickHouse. TestClampExternalLimit pins it so a caller that assumes "I pass
// N, N is what happens" gets a red test instead of a silent surprise.
func clampExternalLimit(limit int) int {
	if limit <= 0 || limit > defaultExternalLimit {
		return defaultExternalLimit
	}
	return limit
}

func (r *CHRepo) ListExternal(ctx context.Context, limit int) ([]Asset, error) {
	limit = clampExternalLimit(limit)
	qCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var ids []string
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			ids = append(ids, id)
		}
		return nil
	}, externalAssetIDs, limit)
	if err != nil {
		return nil, fmt.Errorf("ListExternal: ids: %w", err)
	}

	assets, err := r.byIDsCtx(qCtx, ids)
	if err != nil {
		return nil, fmt.Errorf("ListExternal: %w", err)
	}
	return orderByIDs(ids, assets), nil
}

// IsExposedEdge reports whether the asset has any outgoing exposed_to_internet
// edge in graph_edges. Point query — fast even without FINAL.
func (r *CHRepo) IsExposedEdge(ctx context.Context, assetID string) (bool, error) {
	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var count uint64
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		if rows.Next() {
			return rows.Scan(&count)
		}
		return nil
	}, hasExposedEdge, assetID)
	if err != nil {
		return false, fmt.Errorf("IsExposedEdge: %w", err)
	}
	return count > 0, nil
}

// ExistingIDs returns the subset of ids that currently have an asset row. Order
// is unspecified; missing ids are simply absent. Bounded by the caller (the
// dangling sweep pages a bounded finding batch). Empty input returns nil.
//
// A caller (the dangling sweep) treats any id NOT in the result as "resource
// gone" and auto-resolves its finding — so a partial result here is
// indistinguishable from genuine absence unless we catch it. The explicit
// qCtx.Err() check after Select is belt-and-suspenders against exactly that: if
// the query's deadline fires after some rows already streamed, we want a hard
// error, never a truncated "existing" set silently treated as ground truth.
func (r *CHRepo) ExistingIDs(ctx context.Context, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	placeholders, args := dbutil.CHIn(ids)
	query := fmt.Sprintf(existingAssetIDs, placeholders)

	var out []string
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, id)
		}
		return rows.Err()
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ExistingIDs: %w", err)
	}
	if err := qCtx.Err(); err != nil {
		return nil, fmt.Errorf("ExistingIDs: query deadline: %w", err)
	}
	return out, nil
}

// ProviderHighWater returns the most recent last_seen across a provider's assets
// — when that provider last collected anything. Zero time means the provider has
// no assets at all. See the providerHighWater const for why callers must anchor
// staleness to this rather than to wall-clock time.
func (r *CHRepo) ProviderHighWater(ctx context.Context, provider string) (time.Time, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var out time.Time
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			if err := rows.Scan(&out); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
		}
		return rows.Err()
	}, providerHighWater, provider)
	if err != nil {
		return time.Time{}, fmt.Errorf("ProviderHighWater: %w", err)
	}
	return out, nil
}

// AllEdgesForSync returns the full current edge set for bulk Ladybug sync.
//
// Two-pass strategy — attack-path critical edges are loaded with NO limit so they
// always appear in the graph regardless of how large connected_via_sg or depends_on
// grow. Bulk context edges are loaded in a second pass capped at syncBulkEdgeLimit.
func (r *CHRepo) AllEdgesForSync(ctx context.Context, proj SyncProjection) (EdgeSyncResult, error) {
	// Both passes append into ONE slice, and the bulk pass is read back as a view
	// over its tail. Scanning into two slices and concatenating them at the end
	// would build a third, full-size copy of the edge set while both halves are
	// still live — at scale that transient doubling lands on the worker's heap at
	// exactly the moment the graph rebuild is already at its peak.
	// Built once, outside the row loop: the projection is fixed for the whole sweep.
	var edgePropKeep map[string]struct{}
	if len(proj.EdgePropertyKeys) > 0 {
		edgePropKeep = make(map[string]struct{}, len(proj.EdgePropertyKeys))
		for _, k := range proj.EdgePropertyKeys {
			edgePropKeep[k] = struct{}{}
		}
	}
	var all []Edge
	scanEdges := func(qCtx context.Context, q string) error {
		return r.ch.Select(qCtx, func(rows driver.Rows) error {
			for rows.Next() {
				var (
					e        Edge
					propJSON string
				)
				if err := rows.Scan(&e.SrcID, &e.SrcType, &e.DstID, &e.DstType, &e.EdgeType, &propJSON); err != nil {
					return fmt.Errorf("scan: %w", err)
				}
				if len(proj.EdgePropertyKeys) > 0 {
					e.Properties = decodeMapKeep(propJSON, edgePropKeep)
				} else {
					e.Properties = decodeMap(propJSON)
				}
				all = append(all, e)
			}
			return nil
		}, q)
	}

	// Pass 1: critical attack-path edges — no limit, these are comparatively small.
	critCtx, critCancel := context.WithTimeout(ctx, 30*time.Second)
	defer critCancel()
	if err := scanEdges(critCtx, criticalEdgesQ); err != nil {
		return EdgeSyncResult{}, fmt.Errorf("AllEdgesForSync critical: %w", err)
	}
	criticalCount := len(all)

	// Pass 2: bulk context edges — capped per type and in total (bulkEdgesQ).
	var res EdgeSyncResult
	bulkCtx, bulkCancel := context.WithTimeout(ctx, 120*time.Second)
	defer bulkCancel()
	if err := scanEdges(bulkCtx, bulkEdgesQ); err != nil {
		// Bulk edges are enrichment only — log and continue with critical edges,
		// but record the failure so the graph build knows coverage is partial.
		res.BulkPassFailed = true
		log.FromContext(ctx).Warn().Err(err).Msg("asset: AllEdgesForSync bulk pass failed — graph has critical edges only")
	}
	res.TruncatedTypes = bulkTruncation(all, criticalCount, syncBulkPerTypeLimit, syncBulkEdgeLimit)
	if len(res.TruncatedTypes) > 0 {
		log.FromContext(ctx).Warn().
			Interface("truncated_types", res.TruncatedTypes).
			Msg("asset: AllEdgesForSync bulk edges hit a cap — context edges partial for these types")
	}

	res.Edges = all
	log.FromContext(ctx).Info().
		Int("critical", criticalCount).
		Int("bulk", len(all)-criticalCount).
		Int("total", len(res.Edges)).
		Msg("asset: AllEdgesForSync complete")
	return res, nil
}

// bulkTruncation reports which edge types the bulk pass covered only partially:
// a type that hit its per-type cap, and — when the shared total cap fired — every
// bulk type, because the tail types (the query orders before capping) are missing
// rows in a way per-type counts cannot attribute.
//
// It takes the whole edge slice plus the index the bulk pass started at, because
// the accounting must see the BULK rows only. The two passes share one slice (see
// AllEdgesForSync), and counting the uncapped critical rows too would attribute
// truncation to types that were never capped.
func bulkTruncation(all []Edge, criticalCount, perTypeLimit, totalLimit int) map[string]bool {
	bulk := all[criticalCount:]
	out := map[string]bool{}
	perType := map[string]int{}
	for i := range bulk {
		perType[bulk[i].EdgeType]++
	}
	for et, n := range perType {
		if n >= perTypeLimit {
			out[et] = true
		}
	}
	if len(bulk) >= totalLimit {
		for _, et := range bulkEdgeTypes {
			out[et] = true
		}
	}
	return out
}

// defaultTypeLimit caps a by-type listing. Package inventories run far larger
// than the general inventory view, so the cap is its own, higher ceiling.
const defaultTypeLimit = 20000

func (r *CHRepo) ListByType(ctx context.Context, assetType string, limit int) ([]Asset, error) {
	if limit <= 0 || limit > defaultTypeLimit {
		limit = defaultTypeLimit
	}
	qCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var ids []string
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			ids = append(ids, id)
		}
		return nil
	}, assetIDsByType, assetType, limit)
	if err != nil {
		return nil, fmt.Errorf("ListByType: ids: %w", err)
	}

	assets, err := r.byIDsCtx(qCtx, ids)
	if err != nil {
		return nil, fmt.Errorf("ListByType: %w", err)
	}
	return orderByIDs(ids, assets), nil
}

// EdgesFrom returns the outgoing edges for a batch of source asset IDs — the
// repository half of one blast-radius hop.
func (r *CHRepo) EdgesFrom(ctx context.Context, srcIDs []string) ([]Edge, error) {
	if len(srcIDs) == 0 {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	placeholders, args := dbutil.CHIn(srcIDs)
	query := fmt.Sprintf(outgoingEdges, placeholders)

	var edges []Edge
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				e        Edge
				propJSON string
			)
			if err := rows.Scan(&e.SrcID, &e.SrcType, &e.DstID, &e.DstType, &e.EdgeType, &propJSON); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			e.Properties = decodeMap(propJSON)
			edges = append(edges, e)
		}
		return nil
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("EdgesFrom: %w", err)
	}
	return edges, nil
}

// EdgesTo returns the incoming edges for a batch of destination asset IDs — the
// repository half of one reverse blast-radius hop ("who can reach these?").
func (r *CHRepo) EdgesTo(ctx context.Context, dstIDs []string) ([]Edge, error) {
	if len(dstIDs) == 0 {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	placeholders, args := dbutil.CHIn(dstIDs)
	query := fmt.Sprintf(incomingEdges, placeholders)

	var edges []Edge
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				e        Edge
				propJSON string
			)
			if err := rows.Scan(&e.SrcID, &e.SrcType, &e.DstID, &e.DstType, &e.EdgeType, &propJSON); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			e.Properties = decodeMap(propJSON)
			edges = append(edges, e)
		}
		return nil
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("EdgesTo: %w", err)
	}
	return edges, nil
}

// EdgesOut returns edges of edgeType whose source is srcID — the outgoing
// typed lookup for identity-chain edges (executes_as, has_role, deploys_to).
// Unlike EdgesFrom (which returns all edge types for a batch of IDs), this
// filters in ClickHouse so high-connectivity assets don't over-fetch.
func (r *CHRepo) EdgesOut(ctx context.Context, srcID, edgeType string) ([]Edge, error) {
	if srcID == "" || edgeType == "" {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var edges []Edge
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				e        Edge
				propJSON string
			)
			if err := rows.Scan(&e.SrcID, &e.SrcType, &e.DstID, &e.DstType, &e.EdgeType, &propJSON); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			e.Properties = decodeMap(propJSON)
			edges = append(edges, e)
		}
		return nil
	}, outgoingEdgesByType, srcID, edgeType)
	if err != nil {
		return nil, fmt.Errorf("EdgesOut: %w", err)
	}
	return edges, nil
}

// EdgesOutBatch returns edges of edgeType for all srcIDs in one query —
// replaces the per-repo loop in buildSupplyChainPath (N CH queries → 1).
func (r *CHRepo) EdgesOutBatch(ctx context.Context, srcIDs []string, edgeType string) ([]Edge, error) {
	if len(srcIDs) == 0 || edgeType == "" {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	placeholders, args := dbutil.CHIn(srcIDs)
	args = append(args, edgeType)
	query := fmt.Sprintf(
		`SELECT src_id, src_type, dst_id, dst_type, edge_type, argMax(properties, synced_at)
		FROM graph_edges WHERE src_id IN (%s) AND edge_type = ? AND `+graphschema.EdgeFreshnessCond+`
		GROUP BY src_id, src_type, dst_id, dst_type, edge_type`,
		placeholders,
	)

	var edges []Edge
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				e        Edge
				propJSON string
			)
			if err := rows.Scan(&e.SrcID, &e.SrcType, &e.DstID, &e.DstType, &e.EdgeType, &propJSON); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			e.Properties = decodeMap(propJSON)
			edges = append(edges, e)
		}
		return nil
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("EdgesOutBatch: %w", err)
	}
	return edges, nil
}

// EdgesInto returns edges of edgeType whose destination is dstID — the inbound
// lineage of one asset (e.g. the repos that deploy_to a workload).
func (r *CHRepo) EdgesInto(ctx context.Context, dstID, edgeType string) ([]Edge, error) {
	if dstID == "" || edgeType == "" {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var edges []Edge
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				e        Edge
				propJSON string
			)
			if err := rows.Scan(&e.SrcID, &e.SrcType, &e.DstID, &e.DstType, &e.EdgeType, &propJSON); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			e.Properties = decodeMap(propJSON)
			edges = append(edges, e)
		}
		return nil
	}, incomingEdgesByType, dstID, edgeType)
	if err != nil {
		return nil, fmt.Errorf("EdgesInto: %w", err)
	}
	return edges, nil
}

// EdgesIntoTypes returns edges of any of edgeTypes pointing AT dstID, in one
// query — the inbound lineage across several relationship types at once (replaces
// N EdgesInto calls when sizing remediation impact/dependents).
func (r *CHRepo) EdgesIntoTypes(ctx context.Context, dstID string, edgeTypes []string) ([]Edge, error) {
	if dstID == "" || len(edgeTypes) == 0 {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	placeholders, args := dbutil.CHIn(edgeTypes)
	args = append([]any{dstID}, args...)
	query := fmt.Sprintf(
		`SELECT src_id, src_type, dst_id, dst_type, edge_type, argMax(properties, synced_at)
		FROM graph_edges WHERE dst_id = ? AND edge_type IN (%s) AND `+graphschema.EdgeFreshnessCond+`
		GROUP BY src_id, src_type, dst_id, dst_type, edge_type`,
		placeholders,
	)

	var edges []Edge
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				e        Edge
				propJSON string
			)
			if err := rows.Scan(&e.SrcID, &e.SrcType, &e.DstID, &e.DstType, &e.EdgeType, &propJSON); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			e.Properties = decodeMap(propJSON)
			edges = append(edges, e)
		}
		return nil
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("EdgesIntoTypes: %w", err)
	}
	return edges, nil
}

func encodeMap(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func decodeMap(s string) map[string]string {
	if s == "" || s == "{}" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	return m
}

// decodeMapKeep decodes metadata JSON keeping ONLY the requested keys, without
// allocating the values it discards.
//
// This exists because the Ladybug bulk sync reads a small handful of metadata
// keys per asset type while some types (gcp_service_account, iam_role) carry
// large permission/policy blobs the graph loader never looks at — decoding
// and discarding those blobs on every sync asset costs meaningful heap on a
// worker with a fixed memory budget. It scans rather than unmarshalling
// because unmarshal-then-filter still allocates every discarded value before
// dropping it.
//
// The fast path assumes what the collectors actually store: a flat object of
// string to string. Anything not matching that shape (nested object, number,
// malformed document) falls back to decodeMap and filters its result, so a
// projected read can never disagree with an unprojected one about the same
// asset. TestDecodeMapKeepMatchesDecodeMap and FuzzDecodeMapKeep pin that
// equivalence.
func decodeMapKeep(s string, keep map[string]struct{}) map[string]string {
	if s == "" || s == "{}" || len(keep) == 0 {
		return nil
	}
	if m, ok := scanFlatStringMap(s, keep); ok {
		return m
	}
	// Not the flat all-strings shape. Defer to the general decoder and filter, so
	// behaviour matches an unprojected read exactly (including decodeMap's
	// all-or-nothing nil on a non-string value).
	full := decodeMap(s)
	if full == nil {
		return nil
	}
	var out map[string]string
	for k, v := range full {
		if _, want := keep[k]; !want {
			continue
		}
		if out == nil {
			// No size hint deliberately: sizing to len(keep) allocates buckets for the
			// whole requested set, while the typical asset or edge matches only a
			// handful of them — the hint costs more than the keys it saves.
			out = make(map[string]string)
		}
		out[k] = v
	}
	return out
}

// scanFlatStringMap parses a flat JSON object of string keys to string values,
// materialising only the values whose keys are in keep. ok is false when the input is
// not that shape; a partial result is never returned alongside ok=false.
func scanFlatStringMap(s string, keep map[string]struct{}) (map[string]string, bool) {
	// encoding/json rewrites invalid UTF-8 to U+FFFD; slicing the input preserves the
	// bad bytes. Rather than reproduce that rewrite, refuse the document and let the
	// fallback produce json's answer. One linear scan with no allocation.
	if !utf8.ValidString(s) {
		return nil, false
	}
	i := skipJSONWS(s, 0)
	if i >= len(s) || s[i] != '{' {
		return nil, false
	}
	i = skipJSONWS(s, i+1)
	if i < len(s) && s[i] == '}' {
		if skipJSONWS(s, i+1) != len(s) {
			return nil, false
		}
		return nil, true // empty object: the same nil decodeMap returns
	}

	var out map[string]string
	for {
		if i >= len(s) || s[i] != '"' {
			return nil, false
		}
		keyStart := i
		keyEnd, ok := scanJSONString(s, i)
		if !ok {
			return nil, false
		}
		i = skipJSONWS(s, keyEnd)
		if i >= len(s) || s[i] != ':' {
			return nil, false
		}
		i = skipJSONWS(s, i+1)

		// A non-string value means this is not the flat shape: bail to the fallback.
		if i >= len(s) || s[i] != '"' {
			return nil, false
		}
		valStart := i
		valEnd, ok := scanJSONString(s, i)
		if !ok {
			return nil, false
		}
		i = valEnd

		key, ok := unquoteJSONString(s[keyStart:keyEnd])
		if !ok {
			return nil, false
		}
		if _, want := keep[key]; want {
			val, valOK := unquoteJSONString(s[valStart:valEnd])
			if !valOK {
				return nil, false
			}
			if out == nil {
				out = make(map[string]string) // no hint — see decodeMapKeep's fallback
			}
			out[key] = val
		}
		// A discarded value is never sliced into a new string. That is the point.

		i = skipJSONWS(s, i)
		if i >= len(s) {
			return nil, false
		}
		switch s[i] {
		case ',':
			i = skipJSONWS(s, i+1)
		case '}':
			if skipJSONWS(s, i+1) != len(s) {
				return nil, false // trailing content: not a lone object
			}
			return out, true
		default:
			return nil, false
		}
	}
}

// scanJSONString returns the index one past the closing quote of the JSON string
// starting at s[i] (which must be '"').
//
// It VALIDATES rather than merely locating the end, because the fast path must be
// exactly as strict as encoding/json even for values it discards — an
// unvalidating scan that accepts an illegal escape would make a projected read
// disagree with an unprojected one about the same asset, the one thing this
// design promises cannot happen.
func scanJSONString(s string, i int) (int, bool) {
	i++ // opening quote
	for i < len(s) {
		c := s[i]
		switch {
		case c == '"':
			return i + 1, true
		case c == '\\':
			if i+1 >= len(s) {
				return 0, false
			}
			switch s[i+1] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i += 2
			case 'u':
				if i+5 >= len(s) || !isHex4(s[i+2:i+6]) {
					return 0, false
				}
				i += 6
			default:
				return 0, false // not a JSON escape
			}
		case c < 0x20:
			return 0, false // raw control character: JSON forbids it, so does encoding/json
		default:
			i++
		}
	}
	return 0, false
}

func isHex4(s string) bool {
	if len(s) < 4 {
		return false
	}
	for i := 0; i < 4; i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// unquoteJSONString converts a quoted JSON string span to its value. The common case
// has no escapes and slices directly; escaped strings go through strconv.Unquote.
func unquoteJSONString(quoted string) (string, bool) {
	if len(quoted) < 2 {
		return "", false
	}
	body := quoted[1 : len(quoted)-1]
	if !strings.ContainsRune(body, '\\') {
		// strings.Clone is load-bearing, not defensive. A Go substring SHARES the
		// backing array, so returning body would make every kept small value pin
		// the ENTIRE raw JSON document for as long as the Asset or Edge lives —
		// clawing back most of the projection's memory win, since the same
		// document often also carries a large discarded value the projection
		// exists to drop. Value equality comparisons in tests can't see this
		// (an aliased string still compares equal); it only shows up in heap
		// retention.
		return strings.Clone(body), true
	}
	v, err := strconv.Unquote(quoted)
	if err != nil {
		return "", false
	}
	return v, true
}

func skipJSONWS(s string, i int) int {
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}
