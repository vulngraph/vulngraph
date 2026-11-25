package asset

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/jackc/pgx/v5"

	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// DriftKind describes what changed.
type DriftKind string

const (
	DriftKindNewAsset        DriftKind = "new_asset"        // first seen in this window
	DriftKindNewExposure     DriftKind = "new_exposure"     // gained exposed_to_internet edge
	DriftKindRemovedExposure DriftKind = "removed_exposure" // lost exposed_to_internet edge
	DriftKindChanged         DriftKind = "changed"          // hash changed — IP or name differs
)

// DriftEvent is a single inventory change detected between sweeps.
// AssetID is the full resource identifier — ARN for AWS, resource name for GCP.
type DriftEvent struct {
	Kind       DriftKind `json:"kind"`
	AssetID    string    `json:"asset_id"`
	AssetName  string    `json:"asset_name"`
	AssetType  string    `json:"asset_type"`
	Provider   string    `json:"provider"`
	AccountID  string    `json:"account_id"`
	Region     string    `json:"region,omitempty"`
	PublicIP   string    `json:"public_ip,omitempty"`
	PrivateIP  string    `json:"private_ip,omitempty"`
	Domain     string    `json:"domain,omitempty"`
	Endpoint   string    `json:"endpoint,omitempty"`
	DetectedAt time.Time `json:"detected_at"`
	// Enrichment — added at query time. FindingsKnown is false when the
	// findings lookup failed: FindingsCount and MaxScore are then 0 because
	// nothing was read, not because the asset has no open findings.
	FindingsCount int  `json:"findings_count"` // open findings on this asset
	MaxScore      int  `json:"max_score"`      // worst enriched score (0 = none)
	FindingsKnown bool `json:"findings_known"`
	// Change context — what changed and why
	Why      string `json:"why,omitempty"`       // human-readable explanation
	OldValue string `json:"old_value,omitempty"` // previous state (for changes)
	NewValue string `json:"new_value,omitempty"` // current state
	Field    string `json:"field,omitempty"`     // what field changed
}

// driftNewAssets returns assets first seen within the lookback window.
//
// The predicate is a raw WHERE on first_discovered_at, not discovered_at:
// every collector stamps discovered_at with `now` on every sweep, so it means
// "last collected", not "first discovered", and would match the entire
// estate on any lookback. first_discovered_at is immutable — pinned once at
// Service.pinFirstDiscoveredAt and carried forward on every write — so a
// pre-aggregation WHERE on it is correct. The firstDiscoveredAtAgg minIf
// wrapper in the SELECT is belt-and-suspenders for rows written before that
// column existed, matching finding/repo.go's read of first_detected_at.
//
// inventoryReadCond keeps dead ephemeral resources and IaC declaration rows
// out of the feed, as on every other UI-facing asset read.
var driftNewAssets = `
SELECT
    id,
    argMax(name, synced_at)        AS name,
    argMax(type, synced_at)        AS asset_type,
    argMax(provider, synced_at)    AS provider,
    argMax(account_id, synced_at)  AS account_id,
    argMax(region, synced_at)      AS region,
    argMax(public_ip, synced_at)   AS public_ip,
    argMax(private_ip, synced_at)  AS private_ip,
    argMax(domain, synced_at)      AS domain,
    argMax(endpoint, synced_at)    AS endpoint,
    ` + firstDiscoveredAtAgg + ` AS detected_at
FROM assets
WHERE first_discovered_at >= now() - INTERVAL ? SECOND
  AND ` + inventoryReadCond + `
GROUP BY id
ORDER BY detected_at DESC
LIMIT ?
`

// driftNewExposures returns assets that gained an exposed_to_internet edge
// within the lookback window (i.e. became externally reachable).
// inventoryReadCond filters the joined asset rows before aggregation, as in
// driftNewAssets; its bare type and last_seen resolve to the assets side
// because graph_edges has neither column.
var driftNewExposures = `
SELECT
    e.src_id                              AS id,
    argMax(a.name, a.synced_at)           AS name,
    argMax(a.type, a.synced_at)           AS asset_type,
    argMax(a.provider, a.synced_at)       AS provider,
    argMax(a.account_id, a.synced_at)     AS account_id,
    argMax(a.region, a.synced_at)         AS region,
    argMax(a.public_ip, a.synced_at)      AS public_ip,
    argMax(a.private_ip, a.synced_at)     AS private_ip,
    argMax(a.domain, a.synced_at)         AS domain,
    argMax(a.endpoint, a.synced_at)       AS endpoint,
    max(e.synced_at)                      AS detected_at
FROM graph_edges e
JOIN assets a ON e.src_id = a.id
WHERE e.edge_type = 'exposed_to_internet'
  AND e.synced_at >= now() - INTERVAL ? SECOND
  AND ` + inventoryReadCond + `
GROUP BY e.src_id
ORDER BY detected_at DESC
LIMIT ?
`

// mergeDriftEvents sorts a combined new+changed event set newest-first and
// truncates to limit. Each source query already applies its own LIMIT, so
// without this step a multi-query merge can return up to N times the
// requested limit, ordered as "all of query 1, then all of query 2" rather
// than one true newest-first feed — the frontend needs both the order and
// the count to reflect the whole merged set.
func mergeDriftEvents(events []DriftEvent, limit int) []DriftEvent {
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].DetectedAt.After(events[j].DetectedAt)
	})
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events
}

// DriftEvents returns recent inventory changes within the lookback window,
// newest-first, truncated to limit.
func (r *CHRepo) DriftEvents(ctx context.Context, since time.Duration, limit int) ([]DriftEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	secs := int(since.Seconds())

	var events []DriftEvent

	scanRow := func(rows driver.Rows, kind DriftKind) error {
		for rows.Next() {
			var ev DriftEvent
			if err := rows.Scan(
				&ev.AssetID, &ev.AssetName, &ev.AssetType,
				&ev.Provider, &ev.AccountID, &ev.Region,
				&ev.PublicIP, &ev.PrivateIP, &ev.Domain, &ev.Endpoint,
				&ev.DetectedAt,
			); err != nil {
				return fmt.Errorf("scan %s: %w", kind, err)
			}
			ev.Kind = kind
			events = append(events, ev)
		}
		return nil
	}

	// New assets
	err := r.ch.Select(ctx, func(rows driver.Rows) error {
		return scanRow(rows, DriftKindNewAsset)
	}, driftNewAssets, secs, limit)
	if err != nil {
		return nil, fmt.Errorf("DriftEvents new_asset: %w", err)
	}

	// New exposures
	err = r.ch.Select(ctx, func(rows driver.Rows) error {
		return scanRow(rows, DriftKindNewExposure)
	}, driftNewExposures, secs, limit)
	if err != nil {
		return nil, fmt.Errorf("DriftEvents new_exposure: %w", err)
	}

	events = mergeDriftEvents(events, limit)
	return r.enrichWithFindings(ctx, events), nil
}

// findingsForAssets returns finding counts and worst score per resource_id.
// Inner GROUP BY on (id, resource_id) collapses ReplacingMergeTree versions
// without FINAL — same shape as finding.riskByResourceForIDs; a single-level
// max(argMax(...)) is ClickHouse error 184 (nested aggregates) and also
// counts duplicate row versions.
//
// Only open findings count (the latest version's resolved_at is the zero
// DateTime, same HAVING as finding.riskByResourceForIDs): the event says
// "open findings on this asset", and a resolved finding's score must not
// inflate MaxScore.
//
// Score comes from finding_enrichment via a LEFT JOIN. The join subquery is
// scoped by its own `id IN (SELECT id FROM findings WHERE resource_id IN
// (%s))`, not an unconditional `GROUP BY id` over the whole table — that
// scoping is what keeps this from becoming a full finding_enrichment
// aggregation on every call. The %s placeholder therefore appears twice, so
// the caller binds the id list twice.
const findingsForAssets = `
SELECT resource_id,
    count()          AS cnt,
    max(inner_score) AS max_score
FROM (
    SELECT resource_id, id
    FROM findings
    WHERE resource_id IN (%s)
    GROUP BY id, resource_id
    HAVING argMax(resolved_at, synced_at) < toDateTime('2000-01-01 00:00:00')
) legacy
LEFT JOIN (
    SELECT id, argMax(score, enriched_at) AS inner_score
    FROM finding_enrichment
    WHERE id IN (SELECT id FROM findings WHERE resource_id IN (%s))
    GROUP BY id
) fe ON legacy.id = fe.id
GROUP BY resource_id
`

func (r *CHRepo) enrichWithFindings(ctx context.Context, events []DriftEvent) []DriftEvent {
	if len(events) == 0 {
		return events
	}
	ids := make([]string, 0, len(events))
	for _, e := range events {
		ids = append(ids, e.AssetID)
	}

	var rows []driftFindingRow
	// The %s placeholder appears twice in findingsForAssets (the findings
	// filter and the finding_enrichment join's own id scope), so the
	// id list is bound twice too — ClickHouse binds positionally by where the
	// ?s appear in the text, not by name (same reasoning as
	// finding.RiskByResource).
	placeholders, args := dbutil.CHIn(ids)
	query := fmt.Sprintf(findingsForAssets, placeholders, placeholders)
	args = append(args, args...)
	if err := r.ch.Select(ctx, func(rs driver.Rows) error {
		for rs.Next() {
			var rr driftFindingRow
			if err := rs.Scan(&rr.id, &rr.cnt, &rr.score); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			rows = append(rows, rr)
		}
		return rs.Err()
	}, query, args...); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("drift: finding enrichment query failed; findings reported as unknown")
		return applyDriftFindings(events, nil, false)
	}
	return applyDriftFindings(events, rows, true)
}

type driftFindingRow struct {
	id    string
	cnt   uint64
	score uint8
}

// applyDriftFindings stamps each event with its finding count and worst
// score. known=false (the lookup failed) leaves FindingsKnown false so the
// zero counts read as unknown rather than as "no findings".
func applyDriftFindings(events []DriftEvent, rows []driftFindingRow, known bool) []DriftEvent {
	idx := make(map[string]driftFindingRow, len(rows))
	for _, rr := range rows {
		idx[rr.id] = rr
	}
	for i := range events {
		events[i].FindingsKnown = known
		if rr, ok := idx[events[i].AssetID]; ok {
			events[i].FindingsCount = int(rr.cnt)
			events[i].MaxScore = int(rr.score)
		}
		events[i].Why = whyDriftEvent(events[i])
	}
	return events
}

// whyDriftEvent returns a human-readable explanation of why this drift event occurred.
func whyDriftEvent(e DriftEvent) string {
	switch e.Kind {
	case DriftKindNewAsset:
		switch e.AssetType {
		case "github_repo":
			return "New GitHub repository detected — first seen in this sync sweep."
		case "k8s_pod", "k8s_deployment":
			return "New Kubernetes workload scheduled — likely from a recent deployment or restart."
		case "ec2_instance":
			if e.PublicIP != "" {
				return "New EC2 instance launched with a public IP — verify this is expected and check security groups."
			}
			return "New EC2 instance launched — verify it was intentionally provisioned."
		case "gce_instance":
			return "New GCE instance started — verify it was intentionally launched."
		case "load_balancer":
			return "New load balancer created — review listener rules and target group membership."
		case "rds_instance":
			return "New RDS database instance provisioned — verify network access and encryption settings."
		case "s3_bucket", "gcs_bucket":
			return "New storage bucket created — verify public access settings and encryption."
		case "iam_role", "gcp_service_account":
			return "New IAM identity created — review attached policies and trust relationships."
		case "dns_record":
			return "New DNS record added — verify target is owned and not susceptible to takeover."
		case "security_group":
			return "New security group created — review inbound/outbound rules."
		case "lambda_function":
			return "New Lambda function deployed — review execution role permissions and triggers."
		default:
			return "Asset first seen in this sync sweep — recently created or newly discovered by the connector."
		}
	case DriftKindNewExposure:
		if e.Field == "public_ip,name" {
			return fmt.Sprintf("Asset became internet-reachable — gained a public IP (%s) and was renamed in the same sync. Verify this exposure is intentional and the resource was not replaced.", e.PublicIP)
		}
		if e.PublicIP != "" {
			return fmt.Sprintf("Asset became internet-reachable — gained a public IP (%s) and an exposed_to_internet edge in the graph.", e.PublicIP)
		}
		if e.Domain != "" {
			return fmt.Sprintf("Asset became internet-reachable — DNS (%s) now resolves to this asset via the graph.", e.Domain)
		}
		return "Asset became internet-reachable — gained an exposed_to_internet edge in the security graph. Verify this exposure is intentional."
	case DriftKindRemovedExposure:
		return "Asset is no longer internet-reachable — lost its exposed_to_internet edge. This is usually good news — confirm the change was intentional."
	case DriftKindChanged:
		switch e.Field {
		case "public_ip":
			return fmt.Sprintf("Asset's public IP changed from %q to %q — verify this reassignment was expected.", e.OldValue, e.NewValue)
		case "name":
			return fmt.Sprintf("Asset was renamed from %q to %q — confirm this was an intentional change.", e.OldValue, e.NewValue)
		case "public_ip,name":
			return "Asset's public IP and name both changed — review whether this resource was replaced or reconfigured."
		default:
			return "Asset content changed since the last sync sweep — review the diff for unexpected configuration changes."
		}
	}
	return ""
}

// pgDriftNew queries connector_asset_hashes for assets first inserted within the
// lookback window (change_count = 0 means the hash was never updated after first insert).
const pgDriftNew = `
SELECT
    asset_id,
    curr_name,
    curr_public_ip,
    first_seen_at
FROM connector_asset_hashes
WHERE first_seen_at >= now() - ($1 * INTERVAL '1 second')
  AND change_count = 0
ORDER BY first_seen_at DESC
LIMIT $2
`

// pgDriftChanged queries connector_asset_hashes for assets whose hash changed within
// the lookback window and whose name or public IP actually differs from before.
const pgDriftChanged = `
SELECT
    asset_id,
    curr_name,
    curr_public_ip,
    prev_name,
    prev_public_ip,
    last_changed_at
FROM connector_asset_hashes
WHERE last_changed_at >= now() - ($1 * INTERVAL '1 second')
  AND change_count > 0
  AND (curr_public_ip != prev_public_ip OR curr_name != prev_name)
ORDER BY last_changed_at DESC
LIMIT $2
`

// classifyHashChange fills a changed asset's Field/OldValue/NewValue and
// Kind from its previous name and public IP. The row is keyed by the stable
// asset ID (connector_asset_hashes' (connector_id, asset_id)), so a rename is
// just another field change and never hides what happened to the IP.
//
// Gaining or losing a public IP is an EXPOSURE change, not a field edit:
// "" -> a real address means this resource is now reachable from the
// internet. Reported as a generic "changed" it renders identically to a pod
// being scheduled — so, e.g., a managed database replica going public could sit
// unnoticed among a batch of churn rows. That holds when the same sync also
// renamed the resource.
func classifyHashChange(ev *DriftEvent, prevName, prevIP string) {
	ipChanged := ev.PublicIP != prevIP
	nameChanged := ev.AssetName != prevName
	switch {
	case ipChanged && nameChanged:
		ev.Field = "public_ip,name"
		ev.OldValue = prevIP + " / " + prevName
		ev.NewValue = ev.PublicIP + " / " + ev.AssetName
	case ipChanged:
		ev.Field = "public_ip"
		ev.OldValue = prevIP
		ev.NewValue = ev.PublicIP
	default:
		// pgDriftChanged's WHERE pre-filters to a name-or-IP diff.
		ev.Field = "name"
		ev.OldValue = prevName
		ev.NewValue = ev.AssetName
	}
	switch {
	case prevIP == "" && ev.PublicIP != "":
		ev.Kind = DriftKindNewExposure
	case prevIP != "" && ev.PublicIP == "":
		ev.Kind = DriftKindRemovedExposure
	default:
		ev.Kind = DriftKindChanged
	}
}

// pgAssetContext fetches type/provider/region/account_id from ClickHouse for a
// batch of asset IDs. Used to enrich the Postgres-sourced drift events.
// inventory is inventoryReadCond on each id's latest row: 0 marks a dead
// ephemeral resource or an IaC declaration, which the feed drops.
var pgAssetContext = `
SELECT
    id,
    argMax(toUInt8(` + inventoryReadCond + `), synced_at) AS inventory,
    argMax(type, synced_at)       AS asset_type,
    argMax(provider, synced_at)   AS provider,
    argMax(account_id, synced_at) AS account_id,
    argMax(region, synced_at)     AS region,
    argMax(domain, synced_at)     AS domain,
    argMax(endpoint, synced_at)   AS endpoint,
    argMax(private_ip, synced_at) AS private_ip
FROM assets
WHERE id IN (%s)
GROUP BY id
`

// assetCtx holds ClickHouse context for one asset.
type assetCtx struct {
	inventory uint8
	assetType string
	provider  string
	accountID string
	region    string
	domain    string
	endpoint  string
	privateIP string
}

// PGDriftEvents queries connector_asset_hashes (Postgres) for new and changed
// assets, then enriches each event with type/provider context from ClickHouse.
// The /api/drift/events handler uses it in place of the ClickHouse-only
// DriftEvents when a Postgres pool is wired.
func (r *CHRepo) PGDriftEvents(ctx context.Context, pool pgDriftPool, since time.Duration, limit int) ([]DriftEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	secs := int(since.Seconds())

	var events []DriftEvent

	// New assets from Postgres.
	rows, err := pool.Query(ctx, pgDriftNew, secs, limit)
	if err != nil {
		return nil, fmt.Errorf("PGDriftEvents new: %w", err)
	}
	for rows.Next() {
		var ev DriftEvent
		var detectedAt time.Time
		if err := rows.Scan(&ev.AssetID, &ev.AssetName, &ev.PublicIP, &detectedAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("PGDriftEvents new scan: %w", err)
		}
		ev.Kind = DriftKindNewAsset
		ev.DetectedAt = detectedAt
		events = append(events, ev)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("PGDriftEvents new rows: %w", err)
	}

	// Changed assets from Postgres.
	rows, err = pool.Query(ctx, pgDriftChanged, secs, limit)
	if err != nil {
		return nil, fmt.Errorf("PGDriftEvents changed: %w", err)
	}
	for rows.Next() {
		ev := DriftEvent{Kind: DriftKindChanged}
		var prevName, prevIP string
		if err := rows.Scan(
			&ev.AssetID, &ev.AssetName, &ev.PublicIP, &prevName, &prevIP, &ev.DetectedAt,
		); err != nil {
			rows.Close()
			return nil, fmt.Errorf("PGDriftEvents changed scan: %w", err)
		}
		classifyHashChange(&ev, prevName, prevIP)
		events = append(events, ev)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("PGDriftEvents changed rows: %w", err)
	}

	if len(events) == 0 {
		return events, nil
	}

	events = r.enrichAssetContext(ctx, events)
	events = mergeDriftEvents(events, limit)
	return r.enrichWithFindings(ctx, events), nil
}

// enrichAssetContext fills in each event's type/provider/region/account/domain/
// endpoint/private-IP from ClickHouse and drops events whose asset is not
// inventory (applyAssetContext). Best-effort: a query failure or a row that
// fails to scan is logged and leaves those events' context fields blank rather
// than failing the feed; the raw drift events (kind, IDs, old/new values) are
// still useful without it.
func (r *CHRepo) enrichAssetContext(ctx context.Context, events []DriftEvent) []DriftEvent {
	ids := make([]string, len(events))
	for i, ev := range events {
		ids[i] = ev.AssetID
	}
	placeholders, args := dbutil.CHIn(ids)
	query := fmt.Sprintf(pgAssetContext, placeholders)
	ctxMap := make(map[string]assetCtx, len(ids))
	var scanFailures int
	if err := r.ch.Select(ctx, func(chRows driver.Rows) error {
		for chRows.Next() {
			var id string
			var ac assetCtx
			if err := chRows.Scan(&id, &ac.inventory, &ac.assetType, &ac.provider, &ac.accountID, &ac.region, &ac.domain, &ac.endpoint, &ac.privateIP); err != nil {
				scanFailures++
				continue
			}
			ctxMap[id] = ac
		}
		return nil
	}, query, args...); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("drift: asset context enrichment query failed")
	} else if scanFailures > 0 {
		log.FromContext(ctx).Warn().Int("scan_failures", scanFailures).
			Msg("drift: asset context enrichment dropped rows that failed to scan")
	}

	return applyAssetContext(events, ctxMap)
}

// applyAssetContext copies each event's ClickHouse context onto it and drops
// the events whose asset is not inventory (a dead ephemeral resource or an IaC
// declaration). An event with no context row is kept: the lookup failed or the
// asset has no ClickHouse row, and neither says it is not inventory.
func applyAssetContext(events []DriftEvent, ctxMap map[string]assetCtx) []DriftEvent {
	kept := events[:0]
	for _, ev := range events {
		ac, ok := ctxMap[ev.AssetID]
		if !ok {
			kept = append(kept, ev)
			continue
		}
		if ac.inventory == 0 {
			continue
		}
		ev.AssetType = ac.assetType
		ev.Provider = ac.provider
		ev.AccountID = ac.accountID
		ev.Region = ac.region
		if ev.Domain == "" {
			ev.Domain = ac.domain
		}
		if ev.Endpoint == "" {
			ev.Endpoint = ac.endpoint
		}
		if ev.PrivateIP == "" {
			ev.PrivateIP = ac.privateIP
		}
		kept = append(kept, ev)
	}
	return kept
}

// pgDriftPool is the narrow pool interface PGDriftEvents needs.
// *pgxpool.Pool satisfies it; the interface keeps the asset package free of a
// hard dependency on pgxpool in non-integration paths.
type pgDriftPool interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// compile-time check: CHRepo satisfies the drift interface.
var _ interface {
	DriftEvents(context.Context, time.Duration, int) ([]DriftEvent, error)
} = (*CHRepo)(nil)
