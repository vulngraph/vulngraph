package correlate

import (
	"slices"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// Correlation reads no finding-risk column. Preserve its owned drift overlay
// without joining every observed version to a complete finding-risk generation.
// The declaration input key, clear and observation ordering rules match the
// effective asset view; integration replay covers both set and clear.
const correlationObservations = `SELECT a.id AS id, a.name AS name, a.type AS type,
 a.account_id AS account_id, a.public_ip AS public_ip, a.private_ip AS private_ip,
 a.domain AS domain, a.tags AS tags, a.provider AS provider,
 a.last_seen AS last_seen, a.synced_at AS synced_at,
 if(a.type = 'declared_k8s_workload' AND d.latest_observed_at > toDateTime(0)
    AND d.input_key = concat(JSONExtractString(a.metadata, 'manifest_key'), char(0), JSONExtractString(a.metadata, 'live_type'), char(0), JSONExtractString(a.metadata, 'namespace')),
    if(JSONExtractString(d.patch, 'drift') = '',
       toJSONString(mapFilter((key,value) -> key != 'drift', JSONExtract(a.metadata, 'Map(String,String)'))),
       JSONMergePatch(a.metadata, d.patch)), a.metadata) AS metadata
 FROM assets AS a
 LEFT JOIN (
  SELECT id, argMax(input_key, observed_at) AS input_key,
   argMax(patch, observed_at) AS patch, max(observed_at) AS latest_observed_at
  FROM asset_annotations WHERE source = 'k8s_manifest_drift' GROUP BY id
 ) AS d ON a.id = d.id`

// Project unused payload out BEFORE building latest-row state. A single tuple
// retains one row's fields together while avoiding nine aggregate states per ID.
// This remains one statement with shared storage snapshots. It does not claim
// a committed source generation across different ClickHouse tables.
const projectedCorrelationTuple = `tuple(name,type,account_id,public_ip,private_ip,domain,tags,
  toJSONString(mapFilter((k,v) -> k IN (%s), JSONExtract(metadata, 'Map(String,String)'))))`

const loadViewSelect = `SELECT id,row.1 AS name,row.2 AS type,row.3 AS account_id,
 row.4 AS public_ip,row.5 AS private_ip,row.6 AS domain,row.7 AS tags,row.8 AS metadata
 FROM (
 SELECT id,argMax(` + projectedCorrelationTuple + `,synced_at) AS row
 FROM `
const loadViewFilter = ` WHERE type IN (%s) AND ` + asset.EphemeralLivenessCond + `
 GROUP BY id)`
const loadViewSource = loadViewSelect + `(` + correlationObservations + `)` + loadViewFilter
const loadViewWithoutAnnotations = loadViewSelect + `assets` + loadViewFilter + ` LIMIT ?` + loadViewSettings

// Only manifest declarations can consume this overlay. Other type-scoped reads
// preserve the same observed rows without building or buffering an unused join.
func loadViewForTypesQuery(types []string) string {
	if slices.Contains(types, "declared_k8s_workload") {
		return loadView
	}
	return loadViewWithoutAnnotations
}

const loadViewSettings = ` SETTINGS query_plan_join_swap_table='false'`
const loadStagedView = loadViewSource + loadViewSettings

func loadStagedForTypesQuery(types []string) string {
	if slices.Contains(types, "declared_k8s_workload") {
		return loadStagedView
	}
	return loadViewSelect + `assets` + loadViewFilter + loadViewSettings
}
