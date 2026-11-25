package finding

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Risk is a resource's finding rollup — how an asset's danger is expressed: an
// asset's risk is its findings.
type Risk struct {
	Count     int
	MaxScore  uint8
	WorstBand string
}

// ResourceRisk pairs a resource id with its risk, for the "riskiest assets" view.
type ResourceRisk struct {
	ResourceID string
	Risk
}

// ResourceSignals is the per-resource security-context rollup projected onto the
// graph's asset nodes (graphstore), so a defender can filter on it directly in
// Cypher (e.g. WHERE n.has_kev AND n.exploitable) instead of leaving the graph
// to aggregate findings by hand.
type ResourceSignals struct {
	MaxScore     uint8  // worst enriched finding score on the resource
	HasKEV       bool   // any finding is a known-exploited vuln (CISA KEV)
	PrivescCount int    // count of ciem_privesc findings (privilege-escalation techniques)
	Exploitable  bool   // an active nuclei scan confirmed a high/critical exposure
	CveID        string // check_id of the highest-scoring supply-chain CVE finding, if any
}

// signalsByResource rolls every current finding up per resource into the signal
// set the graph projects onto asset nodes. Inner GROUP BY on (source, id) collapses
// ReplacingMergeTree versions without FINAL — avoids a full-table merge scan on a
// WHERE-less query. The outer aggregate is per resource_id. One query feeds the
// whole graph rebuild.
//
// Two signal sources are unioned:
//  1. Direct: finding.resource_id → asset (CSPM, nuclei, CIEM)
//  2. Package rollup: supply-chain findings on package purls are propagated to the
//     assets that run those packages via graph_edges (runs_in: pkg → asset).
//     This surfaces KEV/exploitable signals on assets from their dependencies.
//
// cve_id is the check_id of the highest-scoring supply-chain finding per resource
// (non-empty only when source='supply_chain' and check_id starts with 'CVE-').
// It is used to populate the Package node's cve_id column in the Ladybug graph.
//
// score/known_exploited come from finding_enrichment via a LEFT JOIN in all
// three branches, unscoped (no id restriction) like coverage.qOpenFindingBands
// — this whole query is already a WHERE-less full scan of findings by design
// (it feeds one graph rebuild sweep, not a request path), so an unconditional
// finding_enrichment aggregation matches the existing cost shape rather than
// adding a new one, and stays comfortably inside SignalsByResource's context
// timeout for a sweep that runs once per rebuild.
//
// This is not merely a performance choice: findings.score can be WRONG. Rows
// written while producer re-observations still raced enrich writes can hold
// findings.score = 0 while finding_enrichment holds the correct value.
// finding_enrichment is never touched by a producer, so reading from it here
// is correct for those rows too, not just future writes.
const signalsByResource = `
-- Direct signals: resource_id matches the asset directly.
-- Inner query collapses RMT versions per (source, id); outer aggregates per resource.
SELECT resource_id,
    max(max_score)                      AS max_score,
    max(has_kev)                        AS has_kev,
    sum(privesc_cnt)                    AS privesc_count,
    sum(exploit_cnt)                    AS exploitable_count,
    ''                                  AS cve_id
FROM (
    SELECT legacy.resource_id AS resource_id,
        fe.score AS max_score,
        fe.known_exploited AS has_kev,
        toUInt64(legacy.type = 'ciem_privesc') AS privesc_cnt,
        toUInt64(legacy.type = 'nuclei'
            AND legacy.severity IN ('high', 'critical')) AS exploit_cnt
    FROM (
        SELECT id, resource_id,
            argMax(type, synced_at)     AS type,
            argMax(severity, synced_at) AS severity
        FROM findings
        WHERE resource_id != ''
        GROUP BY source, id, resource_id
        HAVING argMax(resolved_at, synced_at) < toDateTime('2000-01-01 00:00:00')
    ) legacy
    LEFT JOIN (
        SELECT id,
            argMax(score, enriched_at)           AS score,
            argMax(known_exploited, enriched_at) AS known_exploited
        FROM finding_enrichment GROUP BY id
    ) fe ON legacy.id = fe.id
)
GROUP BY resource_id
UNION ALL
-- Package rollup: propagate supply-chain KEV/score to the asset that runs the package.
-- graph_edges with edge_type='runs_in' maps package purl (src_id) → asset id (dst_id).
SELECT e.dst_id                       AS resource_id,
    max(f.score)                      AS max_score,
    max(f.known_exploited)            AS has_kev,
    toUInt64(0)                       AS privesc_count,
    toUInt64(0)                       AS exploitable_count,
    ''                                AS cve_id
FROM (
    SELECT legacy.resource_id AS resource_id,
        fe.score AS score,
        fe.known_exploited AS known_exploited
    FROM (
        SELECT id, resource_id
        FROM findings
        WHERE resource_id != '' AND source = 'supply_chain'
        GROUP BY source, id, resource_id
        HAVING argMax(resolved_at, synced_at) < toDateTime('2000-01-01 00:00:00')
    ) legacy
    LEFT JOIN (
        SELECT id,
            argMax(score, enriched_at)           AS score,
            argMax(known_exploited, enriched_at) AS known_exploited
        FROM finding_enrichment GROUP BY id
    ) fe ON legacy.id = fe.id
) f
JOIN (
    -- Every asset that runs the package, not just one. A package (src_id) runs in
    -- N workloads (dst_id) — N rows in graph_edges. The previous argMax(dst_id)
    -- collapsed those to a single asset, so a KEV package on 50 hosts propagated
    -- its exploit signal to only one of them. DISTINCT keeps all (package→asset)
    -- pairs so the signal reaches every affected workload. (No FINAL per house
    -- rule; a lingering stale edge over-propagates until TTL, which is fail-safe.)
    SELECT DISTINCT src_id, dst_id
    FROM graph_edges
    WHERE edge_type = 'runs_in' AND ` + graphschema.EdgeFreshnessCond + `
) e ON f.resource_id = e.src_id
WHERE f.known_exploited = 1
GROUP BY e.dst_id
UNION ALL
-- Supply-chain CVE rollup: per package purl (resource_id), pick the check_id of
-- the highest-scoring CVE finding. This populates the Package node's cve_id column
-- so Ladybug queries can filter on the specific CVE without leaving the graph.
-- NOTE: alias must NOT shadow the column name — ClickHouse resolves WHERE against
-- aliases (code: 184 "aggregate function found in WHERE"). latest_check_id avoids
-- the alias collision with the raw check_id column in this SAME subquery's WHERE
-- filter — hit live while developing this join (reintroducing "AS check_id" here
-- reproduces the exact ILLEGAL_AGGREGATION error this comment already warned about).
SELECT resource_id,
    max(cve_max_score)                      AS max_score,
    max(has_kev)                            AS has_kev,
    toUInt64(0)                             AS privesc_count,
    toUInt64(0)                             AS exploitable_count,
    argMax(latest_check_id, cve_max_score)  AS cve_id
FROM (
    SELECT legacy.resource_id AS resource_id,
        fe.score AS cve_max_score,
        fe.known_exploited AS has_kev,
        legacy.latest_check_id AS latest_check_id
    FROM (
        SELECT id, resource_id,
            argMax(check_id, synced_at) AS latest_check_id
        FROM findings
        WHERE resource_id != '' AND source = 'supply_chain'
            AND check_id LIKE 'CVE-%'
        GROUP BY source, id, resource_id
        HAVING argMax(resolved_at, synced_at) < toDateTime('2000-01-01 00:00:00')
    ) legacy
    LEFT JOIN (
        SELECT id,
            argMax(score, enriched_at)           AS score,
            argMax(known_exploited, enriched_at) AS known_exploited
        FROM finding_enrichment GROUP BY id
    ) fe ON legacy.id = fe.id
)
GROUP BY resource_id`

// SignalsByResource returns the signal rollup for every resource carrying
// findings. Resources with no findings are absent; the graph reads absence as
// "no open findings" and zeroes those nodes' signal properties, so an error here
// must be returned, never an empty map.
func (r *CHRepo) SignalsByResource(ctx context.Context) (map[string]ResourceSignals, error) {
	out := map[string]ResourceSignals{}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				id           string
				maxScore     uint8
				hasKEV       uint8
				privescCount uint64
				exploitCount uint64
				cveID        string
			)
			if err := rows.Scan(&id, &maxScore, &hasKEV, &privescCount, &exploitCount, &cveID); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			existing := out[id]
			// Merge: take the max score / OR the bool flags / sum privesc; prefer non-empty cveID.
			if int(maxScore) > int(existing.MaxScore) {
				existing.MaxScore = maxScore
			}
			if hasKEV != 0 {
				existing.HasKEV = true
			}
			existing.PrivescCount += int(privescCount)
			if exploitCount > 0 {
				existing.Exploitable = true
			}
			if cveID != "" && existing.CveID == "" {
				existing.CveID = cveID
			}
			out[id] = existing
		}
		return nil
	}, signalsByResource)
	if err != nil {
		return nil, fmt.Errorf("SignalsByResource: %w", err)
	}
	return out, nil
}

// riskByResourceForIDs rolls current findings up per resource for a given id set.
// Inner GROUP BY on (id, resource_id) collapses ReplacingMergeTree versions without
// FINAL — avoids a full-table merge scan when resource_id IN (N) prunes the universe.
// %s is the IN placeholder list.
// The inner alias is inner_score, not max_score, to avoid ClickHouse error 184:
// "Aggregate function max(max_score) AS max_score is found inside another
// aggregate function" — the outer argMax(worst_band, max_score) would resolve
// max_score as the outer aggregate rather than the inner column.
//
// score/score_band come from finding_enrichment via a LEFT JOIN. The join
// subquery aliases its own argMax outputs directly as inner_score/worst_band
// — the names the outer aggregation already expects — so there is no bare
// `score`/`score_band` identifier left in this query for a future column
// addition to collide with (the hazard mustFixCoverageBySource's comment
// documents for `enriched_at`).
//
// finding_enrichment carries no resource_id column, so the join side needs
// its OWN `id IN (...)` restriction — an unscoped `GROUP BY id` here would
// aggregate the entire table on every call regardless of how few ids the
// caller asked for. This matters because RiskByResource backs every
// asset-list page via asset.handler.go's riskFor, so an unscoped join here
// would mean one full finding_enrichment aggregation per page load. The %s
// placeholder appears twice in the text, so the caller binds the same id
// list twice.
const riskByResourceForIDs = `SELECT resource_id,
		count() AS cnt, max(inner_score) AS max_score, argMax(worst_band, inner_score) AS worst_band
	FROM (
		SELECT id, resource_id
		FROM findings
		WHERE resource_id IN (%s)
		GROUP BY id, resource_id
		HAVING argMax(resolved_at, synced_at) < toDateTime('2000-01-01 00:00:00')
	) legacy
	LEFT JOIN (
		SELECT id,
			argMax(score, enriched_at)      AS inner_score,
			argMax(score_band, enriched_at) AS worst_band
		FROM finding_enrichment
		WHERE id IN (SELECT id FROM findings WHERE resource_id IN (%s))
		GROUP BY id
	) fe ON legacy.id = fe.id
	GROUP BY resource_id`

// RiskByResource returns the finding rollup for each of the given resource ids
// (asset ids). Resources with no findings are simply absent from the map.
func (r *CHRepo) RiskByResource(ctx context.Context, ids []string) (map[string]Risk, error) {
	out := map[string]Risk{}
	if len(ids) == 0 {
		return out, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// The %s placeholder appears twice in riskByResourceForIDs (the findings
	// filter and the finding_enrichment join's own id scope), so the
	// id list is bound twice too — ClickHouse binds positionally by where the
	// ?s appear in the text, not by name.
	placeholders, args := dbutil.CHIn(ids)
	query := fmt.Sprintf(riskByResourceForIDs, placeholders, placeholders)
	args = append(args, args...)
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				id       string
				risk     Risk
				maxScore uint8
				cnt      uint64
			)
			if err := rows.Scan(&id, &cnt, &maxScore, &risk.WorstBand); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			risk.Count = int(cnt)
			risk.MaxScore = maxScore
			out[id] = risk
		}
		return nil
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("RiskByResource: %w", err)
	}
	return out, nil
}

// riskiestResources lists the resources carrying findings, worst-score first —
// the backbone of the risk-sorted asset inventory. Inner GROUP BY on (source, id)
// collapses ReplacingMergeTree versions without FINAL — avoids a full-table merge
// on a WHERE-less query. resource_id is included because the outer aggregates on it
// and it doesn't vary between versions of the same finding.
//
// score/score_band come from finding_enrichment via a LEFT JOIN, same shape
// as riskByResourceForIDs above.
const riskiestResources = `SELECT resource_id,
		count() AS cnt, max(inner_score) AS max_score, argMax(worst_band, inner_score) AS worst_band
	FROM (
		SELECT id, resource_id
		FROM findings
		WHERE resource_id != ''
		GROUP BY source, id, resource_id
		HAVING argMax(resolved_at, synced_at) < toDateTime('2000-01-01 00:00:00')
	) legacy
	LEFT JOIN (
		SELECT id,
			argMax(score, enriched_at)      AS inner_score,
			argMax(score_band, enriched_at) AS worst_band
		FROM finding_enrichment GROUP BY id
	) fe ON legacy.id = fe.id
	GROUP BY resource_id
	ORDER BY max_score DESC, cnt DESC, resource_id DESC
	LIMIT ?`

// RiskiestResources returns the resources with findings, worst-score first.
func (r *CHRepo) RiskiestResources(ctx context.Context, limit int) ([]ResourceRisk, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var out []ResourceRisk
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				rr       ResourceRisk
				maxScore uint8
				cnt      uint64
			)
			if err := rows.Scan(&rr.ResourceID, &cnt, &maxScore, &rr.WorstBand); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			rr.Count = int(cnt)
			rr.MaxScore = maxScore
			out = append(out, rr)
		}
		return nil
	}, riskiestResources, limit)
	if err != nil {
		return nil, fmt.Errorf("RiskiestResources: %w", err)
	}
	return out, nil
}

// ── Cost-bearing risk ────────────────────────────────────────────────────────
//
// The Cost surface asks a narrower question than "what is riskiest": which
// resources that COST MONEY are also carrying serious findings, because there
// the remediation choice is "fix it" versus "delete it and stop paying". The
// riskiest-resources query cannot answer that — its only predicate is
// resource_id != '', so its top page is dominated by Go modules (package) and
// service accounts (gcp_service_account): things that carry real risk but no
// bill, and for which "remediation cost compounds with spend" is meaningless.
// This is the join that makes the question answerable: findings rolled up per
// resource, restricted to asset types that appear on a cloud invoice.

// costBearingAssetTypes are the asset types that carry a recurring cloud bill:
// compute, stored bytes, managed databases, the network front doors and reserved
// addresses that bill by the hour, and the managed secret/key stores that charge
// a fixed monthly fee per object. Deleting or rightsizing one of these changes
// the invoice.
//
// Deliberately EXCLUDED, with reasons, because the exclusions are the point:
//   - package, container_image — inventory of code, not billed resources
//   - iam_role, iam_user, gcp_service_account, sso_* — identities are free
//   - declared_* — IaC declarations, not running infrastructure
//   - security_group, subnet, vpc, gcp_firewall — free network scaffolding
//   - k8s_*, container, k8s_pod — billed via the node/cluster, not per object;
//     counting them would double-count the compute already counted as instances
//   - dns_record, dns_zone, acm_certificate — per-zone/per-query pennies, and
//     the sheer number of dns_records would swamp every real signal
//   - sqs_queue, sns_topic — usage-priced with no idle cost, so "at risk" says
//     nothing about spend
//
// Types are matched exactly against assets.type. An unknown/new billed type is
// simply absent from this panel until it is added here — silently under-counting
// is the safe direction for a panel whose claim is "these cost money".
var costBearingAssetTypes = []string{
	// Compute
	"ec2_instance", "gce_instance", "azure_webapp",
	"lambda_function", "cloud_function", "cloudrun_service",
	"ecs_service", "ecs_cluster", "eks_cluster", "gke_cluster",
	// Storage
	"ebs_volume", "ebs_snapshot", "ami", "gcp_disk_snapshot", "gcp_image",
	"s3_bucket", "gcs_bucket", "azure_storage_account", "ecr_repository",
	// Managed databases
	"rds_instance", "rds_snapshot", "cloudsql_instance",
	"azure_sql_database", "azure_sql_server",
	// Network front doors / reserved addresses (billed hourly)
	"load_balancer", "gcp_forwarding_rule", "api_gateway",
	"elastic_ip", "azure_public_ip",
	// Fixed monthly fee per object
	"kms_key", "secretsmanager_secret", "gcp_secret",
}

// CostBearingAssetTypes returns the asset types counted as cost-bearing, so the
// API can publish the definition alongside the numbers derived from it. A count
// whose population is undocumented is the defect this whole path is fixing.
func CostBearingAssetTypes() []string {
	out := make([]string, len(costBearingAssetTypes))
	copy(out, costBearingAssetTypes)
	return out
}

// CostAtRiskResource is one cost-bearing resource carrying findings, with enough
// asset context for the UI to render it without a second round trip.
type CostAtRiskResource struct {
	ResourceID string
	Name       string
	Type       string
	Provider   string
	Region     string
	MaxScore   uint8
	Count      int
}

// CostAtRisk is the cost-bearing-risk rollup: the TRUE total plus a bounded
// ranked page of it. Total is a server-side COUNT over the whole population, not
// len(Resources) — the row count of the LIMIT 100 page would read "100" for any
// estate with more than a hundred risky resources and never change.
type CostAtRisk struct {
	MinScore   int
	Total      int            // distinct cost-bearing resources at max_score >= MinScore
	ByType     map[string]int // composition, summing to Total
	ByProvider map[string]int // composition, summing to Total
	Resources  []CostAtRiskResource
}

// costAtRiskFrom is the shared FROM/JOIN of both cost-at-risk queries: current
// findings rolled up per resource (inner GROUP BY on (source, id) collapses
// ReplacingMergeTree versions without FINAL, per CLAUDE.md), inner-joined to the
// cost-bearing asset rows. The join is INNER on purpose: a finding whose
// resource has no asset row is not evidence of a bill.
//
// Score comes from finding_enrichment via a LEFT JOIN. finding_enrichment
// carries no resource_id column, so unlike finding.SignalsByResource (a
// WHERE-less periodic sweep, where an unscoped join matches the existing
// full-scan cost), this join gets its OWN scoping subquery: this endpoint is
// a live request path (GET /api/findings/cost-at-risk), and
// finding_enrichment is comparable in size to findings — an unconditional
// GROUP BY id here would be a full-table aggregation on every hit (the same
// reason riskByResourceForIDs scopes its join). The scope mirrors costBearingAssetTypes on the assets side one
// level down: id IN (SELECT id FROM findings WHERE resource_id IN (SELECT id
// FROM assets WHERE type IN (%s))).
//
// Placeholder order matters and is NOT the order the parameters are named
// in: ClickHouse binds positionally by the order the ?/%s appear in the SQL
// TEXT, and there are TWO %s occurrences (the enrichment scope, then the
// assets WHERE) around the ONE HAVING min_score bind — text order is
// [types..., minScore, types...], so args must be costAtRiskArgs(typeArgs,
// minScore, tail...). Binding them wrong compares a score against a type
// string and silently returns nothing.
//
// Not a const: it concatenates asset.InventoryReadCond, a package-level var
// (aliased from asset.inventoryReadCond, itself built from EphemeralLivenessCond
// + NonInventoryTypes at init time), so this can only be a var too.
var costAtRiskFrom = `
	FROM (
		SELECT resource_id, max(inner_score) AS max_score, count() AS cnt
		FROM (
			SELECT legacy.resource_id AS resource_id, fe.inner_score AS inner_score
			FROM (
				SELECT id, resource_id
				FROM findings
				WHERE resource_id != ''
				GROUP BY source, id, resource_id
				HAVING argMax(resolved_at, synced_at) < toDateTime('2000-01-01 00:00:00')
			) legacy
			LEFT JOIN (
				SELECT id, argMax(score, enriched_at) AS inner_score
				FROM finding_enrichment
				WHERE id IN (
					SELECT id FROM findings
					WHERE resource_id IN (SELECT id FROM assets WHERE type IN (%s) AND ` + asset.InventoryReadCond + `)
				)
				GROUP BY id
			) fe ON legacy.id = fe.id
		)
		GROUP BY resource_id
		HAVING max_score >= ?
	) f
	INNER JOIN (
		SELECT id,
			argMax(type, synced_at)     AS asset_type,
			argMax(provider, synced_at) AS provider,
			argMax(name, synced_at)     AS asset_name,
			argMax(region, synced_at)   AS region
		FROM assets
		WHERE type IN (%s) AND ` + asset.InventoryReadCond + `
		GROUP BY id
	) a ON f.resource_id = a.id`

// costAtRiskComposition is the COUNT half: the true total, broken down by
// provider and type so the number is auditable rather than asserted.
var costAtRiskComposition = `SELECT a.provider AS provider, a.asset_type AS asset_type, count() AS n` +
	costAtRiskFrom + `
	GROUP BY provider, asset_type`

// costAtRiskPage is the ranked-rows half, worst score first.
var costAtRiskPage = `SELECT f.resource_id AS resource_id, a.asset_name AS asset_name,
		a.asset_type AS asset_type, a.provider AS provider, a.region AS region,
		f.max_score AS max_score, f.cnt AS cnt` +
	costAtRiskFrom + `
	ORDER BY max_score DESC, cnt DESC, resource_id DESC
	LIMIT ?`

// costAtRiskArgs builds the positional binds in SQL-TEXT order: the asset-type
// IN list (the enrichment join's own scoping subquery, textually first),
// then min_score (HAVING), then the asset-type IN list AGAIN (the assets
// WHERE), then any trailing binds (LIMIT). Its own function so the order is
// assertable in a unit test — a misordered bind is exactly the kind of
// mistake that returns zero rows instead of an error.
func costAtRiskArgs(typeArgs []any, minScore int, tail ...any) []any {
	args := make([]any, 0, 2*len(typeArgs)+1+len(tail))
	args = append(args, typeArgs...)
	args = append(args, minScore)
	args = append(args, typeArgs...)
	return append(args, tail...)
}

// CostAtRisk returns the cost-bearing resources at or above minScore: the full
// count and composition, plus the top `limit` rows.
func (r *CHRepo) CostAtRisk(ctx context.Context, minScore, limit int) (CostAtRisk, error) {
	out := CostAtRisk{MinScore: minScore, ByType: map[string]int{}, ByProvider: map[string]int{}}

	qCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// Server-side ceiling too, so a slow ClickHouse is killed there and not just
	// waited out here (house pattern; asset.CHRepo.List does the same).
	qCtx = r.ch.WithQuerySettings(qCtx, map[string]any{"max_execution_time": 18})

	typePlaceholders, typeArgs := dbutil.CHIn(costBearingAssetTypes)

	// Composition first: it produces Total, which is meaningful even if the page
	// query is what the eye lands on.
	compArgs := costAtRiskArgs(typeArgs, minScore)
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				provider  string
				assetType string
				n         uint64 // count() is UInt64; downcast explicitly (CLAUDE.md)
			)
			if err := rows.Scan(&provider, &assetType, &n); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out.Total += int(n)
			out.ByType[assetType] += int(n)
			out.ByProvider[provider] += int(n)
		}
		return nil
	}, fmt.Sprintf(costAtRiskComposition, typePlaceholders, typePlaceholders), compArgs...)
	if err != nil {
		return CostAtRisk{}, fmt.Errorf("CostAtRisk: composition: %w", err)
	}

	if limit <= 0 {
		return out, nil
	}
	pageArgs := costAtRiskArgs(typeArgs, minScore, limit)
	err = r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				res      CostAtRiskResource
				maxScore uint8
				cnt      uint64
			)
			if err := rows.Scan(&res.ResourceID, &res.Name, &res.Type, &res.Provider,
				&res.Region, &maxScore, &cnt); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			res.MaxScore = maxScore
			res.Count = int(cnt)
			out.Resources = append(out.Resources, res)
		}
		return nil
	}, fmt.Sprintf(costAtRiskPage, typePlaceholders, typePlaceholders), pageArgs...)
	if err != nil {
		return CostAtRisk{}, fmt.Errorf("CostAtRisk: page: %w", err)
	}
	return out, nil
}

// costAtRiskRepo is the narrow capability CostAtRisk needs. Declared here and
// satisfied by *CHRepo rather than widened onto the package's Repo interface, so
// the in-memory repos used by the service tests do not have to grow a method
// they have no data for.
type costAtRiskRepo interface {
	CostAtRisk(ctx context.Context, minScore, limit int) (CostAtRisk, error)
}

// ErrCostAtRiskUnsupported is returned when the wired repository cannot answer
// the cost-bearing-risk join (only the ClickHouse repo can). Surfaced as an
// error rather than an empty result: a zero here would read as "no cost-bearing
// resource is at risk", which is the exact class of false all-clear this change
// exists to remove.
var ErrCostAtRiskUnsupported = errors.New("finding: cost-at-risk requires the ClickHouse repository")

// CostAtRisk returns cost-bearing resources carrying findings at or above
// minScore — the true count, its composition, and a ranked page.
func (s *Service) CostAtRisk(ctx context.Context, minScore, limit int) (CostAtRisk, error) {
	repo, ok := s.repo.(costAtRiskRepo)
	if !ok {
		return CostAtRisk{}, ErrCostAtRiskUnsupported
	}
	return repo.CostAtRisk(ctx, minScore, limit)
}

// ── HTTP: GET /api/findings/cost-at-risk ─────────────────────────────────────

// costAtRiskResourceResponse is the wire shape of one cost-bearing at-risk resource.
type costAtRiskResourceResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Provider     string `json:"provider"`
	Region       string `json:"region,omitempty"`
	MaxScore     uint8  `json:"max_score"`
	FindingCount int    `json:"finding_count"`
}

// costAtRiskResponse publishes the total SEPARATELY from the returned rows, and
// says how many rows were returned, so a client can never present a page
// size as a population size.
type costAtRiskResponse struct {
	MinScore         int                          `json:"min_score"`
	Total            int                          `json:"total"`
	Returned         int                          `json:"returned"`
	ByType           map[string]int               `json:"by_type"`
	ByProvider       map[string]int               `json:"by_provider"`
	CostBearingTypes []string                     `json:"cost_bearing_types"`
	Items            []costAtRiskResourceResponse `json:"items"`
}

// costAtRiskDefaultLimit bounds the ranked page. The total is a COUNT, so the
// page can stay small without the headline lying about it.
const costAtRiskDefaultLimit = 200

// costAtRiskMaxLimit caps ?limit= — this query joins the whole findings rollup
// against the asset table, so an unbounded page is a denial-of-service.
const costAtRiskMaxLimit = 1000

// CostAtRisk handles GET /api/findings/cost-at-risk?min_score=60&limit=200.
func (h *Handler) CostAtRisk(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	minScore := 60
	if raw := q.Get("min_score"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > 100 {
			errs.WriteHTTPError(w, errs.InvalidInput("min_score must be between 0 and 100"))
			return
		}
		minScore = n
	}
	limit := costAtRiskDefaultLimit
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > costAtRiskMaxLimit {
			errs.WriteHTTPError(w, errs.InvalidInput("limit must be between 0 and 1000"))
			return
		}
		limit = n
	}

	res, err := h.svc.CostAtRisk(r.Context(), minScore, limit)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("cost-at-risk rollup failed")
		errs.WriteHTTPError(w, errs.Internal("failed to compute cost-bearing risk"))
		return
	}

	resp := costAtRiskResponse{
		MinScore:         res.MinScore,
		Total:            res.Total,
		Returned:         len(res.Resources),
		ByType:           res.ByType,
		ByProvider:       res.ByProvider,
		CostBearingTypes: CostBearingAssetTypes(),
		Items:            make([]costAtRiskResourceResponse, len(res.Resources)),
	}
	if resp.ByType == nil {
		resp.ByType = map[string]int{}
	}
	if resp.ByProvider == nil {
		resp.ByProvider = map[string]int{}
	}
	for i, rr := range res.Resources {
		resp.Items[i] = costAtRiskResourceResponse{
			ID: rr.ResourceID, Name: rr.Name, Type: rr.Type, Provider: rr.Provider,
			Region: rr.Region, MaxScore: rr.MaxScore, FindingCount: rr.Count,
		}
	}
	writeJSON(r.Context(), w, http.StatusOK, resp)
}

// RiskByResource returns per-resource finding rollups for the given asset ids.
func (s *Service) RiskByResource(ctx context.Context, ids []string) (map[string]Risk, error) {
	return s.repo.RiskByResource(ctx, ids)
}

// RiskiestResources returns the resources carrying findings, worst-score first.
func (s *Service) RiskiestResources(ctx context.Context, limit int) ([]ResourceRisk, error) {
	return s.repo.RiskiestResources(ctx, limit)
}

// SignalsByResource returns the per-resource signal rollup the graph projects
// onto asset nodes (one query, called per graph rebuild).
func (s *Service) SignalsByResource(ctx context.Context) (map[string]ResourceSignals, error) {
	return s.repo.SignalsByResource(ctx)
}
