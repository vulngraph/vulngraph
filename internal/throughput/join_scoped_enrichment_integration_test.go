//go:build integration

package throughput

// Test-only current-row experiment. All references to each physical table share
// a storage snapshot; enrichment filtering retains only IDs from current open findings.
const scopedSummaryLatestRows = `SELECT sev,band,owner,env,count() FROM (
 SELECT legacy.sev AS sev,fe.band AS band,fe.owner AS owner,fe.env AS env
 FROM (
  SELECT id,severity AS sev FROM findings FINAL
  WHERE resolved_at<toDateTime('2000-01-01 00:00:00')
 ) legacy LEFT JOIN (
  SELECT id,score_band AS band,if(owner_source='none','unowned',owner_team) AS owner,environment AS env
  FROM finding_enrichment FINAL
  WHERE id IN (SELECT id FROM findings FINAL WHERE resolved_at<toDateTime('2000-01-01 00:00:00'))
 ) fe ON legacy.id=fe.id
) GROUP BY sev,band,owner,env SETTINGS enable_shared_storage_snapshot_in_query = 1`

const scopedClustersLatestRows = `SELECT check_id,
 argMax(title,score),argMax(severity,score),any(source),argMax(remediation,score),max(score),
 argMax(score_band,score),count(),uniq(resource_id),max(known_exploited),max(detected_at),count() OVER ()
 FROM (
 SELECT legacy.check_id AS check_id,legacy.source AS source,legacy.resource_id AS resource_id,
 legacy.title AS title,legacy.severity AS severity,legacy.remediation AS remediation,
 fe.score AS score,fe.score_band AS score_band,fe.known_exploited AS known_exploited,legacy.detected_at AS detected_at
 FROM (
  SELECT id,check_id,source,resource_id,title,severity,remediation,detected_at FROM findings FINAL
  WHERE resolved_at<toDateTime('2000-01-01 00:00:00')
 ) legacy LEFT JOIN (
  SELECT id,score,score_band,known_exploited FROM finding_enrichment FINAL
  WHERE id IN (SELECT id FROM findings FINAL WHERE resolved_at<toDateTime('2000-01-01 00:00:00'))
 ) fe ON legacy.id=fe.id
 ) GROUP BY check_id ORDER BY max(score) DESC,count() DESC LIMIT 500 SETTINGS enable_shared_storage_snapshot_in_query = 1`
