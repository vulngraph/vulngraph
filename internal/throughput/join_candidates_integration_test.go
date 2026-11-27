//go:build integration

package throughput

import (
	"context"
	"fmt"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

// This test-only experiment narrows the enrichment aggregation to current open
// finding IDs. It preserves each side's original latest-row and source semantics.
const openJoinIDs = `WITH open_ids AS (
 SELECT id FROM findings %s GROUP BY source,id
 HAVING argMax(resolved_at,synced_at)<toDateTime('2000-01-01 00:00:00')
) `
const boundedEnrichmentSummary = openJoinIDs + `SELECT sev,band,owner,env,count() FROM (
 SELECT legacy.sev AS sev,fe.band AS band,fe.owner AS owner,fe.env AS env FROM (
  SELECT id,argMax(severity,synced_at) AS sev,argMax(resolved_at,synced_at) AS resolved_at
  FROM findings %s GROUP BY source,id HAVING resolved_at<toDateTime('2000-01-01 00:00:00')
 ) legacy LEFT JOIN (
  SELECT id,argMax(score_band,enriched_at) AS band,
   if(argMax(owner_source,enriched_at)='none','unowned',argMax(owner_team,enriched_at)) AS owner,
   argMax(environment,enriched_at) AS env
  FROM finding_enrichment WHERE id IN (SELECT id FROM open_ids) GROUP BY id
 ) fe ON legacy.id=fe.id
) GROUP BY sev,band,owner,env`
const boundedEnrichmentClusters = openJoinIDs + `SELECT check_id,
 argMax(title,score),argMax(severity,score),any(source),argMax(remediation,score),max(score),
 argMax(score_band,score),count(),uniq(resource_id),max(known_exploited),max(detected_at),count() OVER ()
 FROM (
 SELECT legacy.check_id AS check_id,legacy.source AS source,legacy.resource_id AS resource_id,
 legacy.title AS title,legacy.severity AS severity,legacy.remediation AS remediation,
 fe.score AS score,fe.score_band AS score_band,fe.known_exploited AS known_exploited,legacy.detected_at AS detected_at
 FROM (
  SELECT id,check_id,source,resource_id,argMax(title,synced_at) AS title,argMax(severity,synced_at) AS severity,
  argMax(remediation,synced_at) AS remediation,argMax(detected_at,synced_at) AS detected_at,argMax(resolved_at,synced_at) AS resolved_at
  FROM findings %s GROUP BY source,id,check_id,resource_id HAVING resolved_at<toDateTime('2000-01-01 00:00:00')
 ) legacy LEFT JOIN (
  SELECT id,argMax(score,enriched_at) AS score,argMax(score_band,enriched_at) AS score_band,
  argMax(known_exploited,enriched_at) AS known_exploited
  FROM finding_enrichment WHERE id IN (SELECT id FROM open_ids) GROUP BY id
 ) fe ON legacy.id=fe.id
 ) GROUP BY check_id ORDER BY max(score) DESC,count() DESC LIMIT 500`

func joinCandidateSQL(kind, source, experiment string) (string, []any) {
	if experiment == "baseline_rows" {
		where := ""
		var args []any
		if source != "" {
			where = "WHERE source = ?"
			args = append(args, source)
		}
		query := baselineSummaryOpenFindings
		if kind == "clusters" {
			query = baselineClustersByCheck
			args = append(args, 500)
		}
		return fmt.Sprintf(query, where), args
	}
	where := ""
	var args []any
	if source != "" {
		where = "WHERE source=?"
		args = []any{source, source}
	}
	query := boundedEnrichmentSummary
	if kind == "clusters" {
		query = boundedEnrichmentClusters
	}
	return fmt.Sprintf(query, where, where), args
}
func readJoinSummaryCandidate(ctx context.Context, ch *db.CH, source, experiment string) (finding.Summary, error) {
	if experiment == "latest_rows" {
		return finding.NewCHRepo(ch).Summary(ctx, finding.Filter{Source: source})
	}
	out := finding.Summary{BySeverity: map[finding.Severity]int{}, ByBand: map[string]int{}, ByOwner: map[string]int{}, ByEnvironment: map[string]int{}}
	query, args := joinCandidateSQL("summary", source, experiment)
	err := ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var sev, band, owner, env string
			var n uint64
			if err := rows.Scan(&sev, &band, &owner, &env, &n); err != nil {
				return err
			}
			out.Total += int(n)
			out.BySeverity[finding.Severity(sev)] += int(n)
			out.ByOwner[owner] += int(n)
			out.ByEnvironment[env] += int(n)
			if band != "" {
				out.ByBand[band] += int(n)
			}
		}
		return rows.Err()
	}, query, args...)
	return out, err
}
func readJoinClustersCandidate(ctx context.Context, ch *db.CH, source, experiment string) ([]finding.Cluster, int, error) {
	if experiment == "latest_rows" {
		return finding.NewCHRepo(ch).Clusters(ctx, finding.Filter{Source: source})
	}
	var out []finding.Cluster
	var total uint64
	query, args := joinCandidateSQL("clusters", source, experiment)
	err := ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var c finding.Cluster
			var severity string
			var instances, resources uint64
			var kev uint8
			if err := rows.Scan(&c.CheckID, &c.Title, &severity, &c.Source, &c.Remediation, &c.MaxScore, &c.WorstBand, &instances, &resources, &kev, &c.LastDetected, &total); err != nil {
				return err
			}
			c.Severity = finding.Severity(severity)
			c.Instances = int(instances)
			c.Resources = int(resources)
			c.KnownExploited = kev != 0
			out = append(out, c)
		}
		return rows.Err()
	}, query, args...)
	return out, int(total), err
}
