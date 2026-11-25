package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// Cluster collapses every finding of one check into a single row — the unit a
// human actually triages. The same check (e.g. an IAM privilege-escalation rule)
// fires on hundreds of resources; listing each instance buries ~20 real issues
// under thousands of rows. A cluster carries the worst score/band across its
// instances, how many there are, and how many distinct resources they hit.
type Cluster struct {
	CheckID        string
	Title          string
	Severity       Severity
	Source         string
	Remediation    string // how to fix it (representative; the "what to do")
	MaxScore       uint8  // highest enriched score across the cluster's instances
	WorstBand      string // score band of the highest-scoring instance
	Instances      int    // total findings in the cluster
	Resources      int    // distinct resources affected
	KnownExploited bool   // any instance is CISA-KEV
	LastDetected   time.Time
}

// clustersByCheck groups deduplicated open findings by check into clusters.
// The inner GROUP BY (source, id) collapses ReplacingMergeTree versions via
// argMax, not FINAL — a source-filtered FINAL full-scans the table (skip
// indexes don't apply under FINAL; CLAUDE.md). check_id and resource_id are
// baked into the deterministic finding ID so grouping on them is version-safe.
// HAVING drops resolved findings: a fully-remediated check must not
// linger as a cluster carrying its old max_score/KEV flags. %s is the optional
// pre-aggregation source filter.
//
// score/score_band/known_exploited come from finding_enrichment via a LEFT
// JOIN — `findings` carries no enrichment columns. The inner subquery (aliased
// legacy) exposes id so the join can key on it; the outer aggregation picks
// the representative title/severity/remediation by the highest score in the
// cluster via argMax(_, score).
const clustersByCheck = `SELECT
		check_id,
		argMax(title, score)       AS title,
		argMax(severity, score)    AS severity,
		any(source)                AS source,
		argMax(remediation, score) AS remediation,
		max(score)                 AS max_score,
		argMax(score_band, score)  AS worst_band,
		count()                    AS instances,
		uniq(resource_id)          AS resources,
		max(known_exploited)       AS kev,
		max(detected_at)           AS last_detected,
		count() OVER ()            AS total_checks
	FROM (
		SELECT legacy.check_id     AS check_id,
			legacy.source          AS source,
			legacy.resource_id     AS resource_id,
			legacy.title           AS title,
			legacy.severity        AS severity,
			legacy.remediation     AS remediation,
			fe.score                AS score,
			fe.score_band           AS score_band,
			fe.known_exploited      AS known_exploited,
			legacy.detected_at      AS detected_at
		FROM (
			SELECT id, check_id, source, resource_id,
				argMax(title, synced_at)       AS title,
				argMax(severity, synced_at)    AS severity,
				argMax(remediation, synced_at) AS remediation,
				argMax(detected_at, synced_at) AS detected_at,
				argMax(resolved_at, synced_at) AS resolved_at
			FROM findings
			%s
			GROUP BY source, id, check_id, resource_id
			HAVING resolved_at < toDateTime('2000-01-01 00:00:00')
		) legacy
		LEFT JOIN (
			SELECT id,
				argMax(score, enriched_at)          AS score,
				argMax(score_band, enriched_at)     AS score_band,
				argMax(known_exploited, enriched_at) AS known_exploited
			FROM finding_enrichment
			GROUP BY id
		) fe ON legacy.id = fe.id
	)
	GROUP BY check_id
	ORDER BY max_score DESC, instances DESC
	LIMIT ?`

// clusterLimit caps the cluster list. The original "tens of distinct checks"
// assumption is false at scale — every CVE is its own check_id, so the estate
// carries hundreds of clusters and this limit genuinely truncates. total_checks
// (count() OVER (), computed after GROUP BY but before LIMIT) reports the true
// population so the UI can disclose the truncation instead of presenting the
// page size as a total.
const clusterLimit = 500

// Clusters returns findings grouped by check, worst-score first, plus the true
// number of clusters before the LIMIT so callers can disclose truncation.
// Filter.Source narrows the population; other Filter fields are ignored (a
// per-check rollup filtered by score/severity would hide instances that belong
// to the cluster).
func (r *CHRepo) Clusters(ctx context.Context, f Filter) ([]Cluster, int, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	innerWhere := ""
	var args []any
	if f.Source != "" {
		innerWhere = "WHERE source = ?"
		args = append(args, f.Source)
	}
	query := fmt.Sprintf(clustersByCheck, innerWhere)
	args = append(args, clusterLimit)

	var out []Cluster
	var totalChecks uint64
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				c         Cluster
				severity  string
				maxScore  uint8
				kev       uint8
				instances uint64 // count() / uniq() are UInt64; downcast explicitly (CLAUDE.md)
				resources uint64
			)
			if err := rows.Scan(
				&c.CheckID, &c.Title, &severity, &c.Source, &c.Remediation,
				&maxScore, &c.WorstBand, &instances, &resources, &kev, &c.LastDetected,
				&totalChecks,
			); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			c.Severity = Severity(severity)
			c.MaxScore = maxScore
			c.Instances = int(instances)
			c.Resources = int(resources)
			c.KnownExploited = kev != 0
			out = append(out, c)
		}
		return nil
	}, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("Clusters: %w", err)
	}
	return out, int(totalChecks), nil
}

// Clusters returns findings grouped by check, worst-score first — the triage
// view — plus the true cluster count before the LIMIT.
func (s *Service) Clusters(ctx context.Context, f Filter) ([]Cluster, int, error) {
	return s.repo.Clusters(ctx, f)
}
