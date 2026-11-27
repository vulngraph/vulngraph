-- +goose Up
-- Derived state never re-inserts inventory observations. A risk generation is
-- visible only after all its rows committed; failed/partial refreshes retain the
-- preceding published generation. The commit marker is the reserved empty-id
-- row in the SAME table, so enforced shared-storage query snapshots include
-- both the marker and its data. The publication ledger serves cleanup only.
-- Annotation producers own separate keys.
CREATE TABLE asset_finding_risk (
 generation DateTime64(9), digest FixedString(64), id String, risk_score UInt8, pinned UInt8 DEFAULT 0,
 INDEX idx_id id TYPE bloom_filter GRANULARITY 1
) ENGINE = ReplacingMergeTree(pinned)
ORDER BY (generation, digest, id)
TTL toDateTime(generation) + INTERVAL 1 DAY DELETE WHERE pinned = 0;

CREATE TABLE asset_risk_publications (
 generation DateTime64(9), digest FixedString(64),
 updated_at DateTime64(9) DEFAULT now64(9), retired UInt8 DEFAULT 0,
 retired_at DateTime64(9) DEFAULT toDateTime64(0,9)
) ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (generation,digest)
TTL toDateTime(retired_at) + INTERVAL 1 DAY DELETE WHERE retired = 1;

CREATE TABLE asset_annotations (
 source LowCardinality(String), id String, observed_at DateTime64(9),
 input_key String, patch String,
 INDEX idx_id id TYPE bloom_filter GRANULARITY 1
) ENGINE = ReplacingMergeTree(observed_at)
ORDER BY (source, id)
TTL toDateTime(observed_at) + INTERVAL 180 DAY;

-- Keep point reads over raw versions so the id skip index remains available.
CREATE VIEW asset_versions_with_derivations AS
SELECT a.id AS id,
 a.name AS name,
 a.type AS type,
 a.provider AS provider,
 a.region AS region,
 a.account_id AS account_id,
 a.endpoint AS endpoint,
 a.public_ip AS public_ip,
 a.private_ip AS private_ip,
 a.domain AS domain,
 a.tags AS tags,
 a.discovered_at AS discovered_at,
 a.first_discovered_at AS first_discovered_at,
 a.last_seen AS last_seen,
 a.synced_at AS synced_at,
 greatest(a.risk_score, r.risk_score) AS risk_score,
 if(a.type = 'declared_k8s_workload' AND d.latest_observed_at > toDateTime(0)
    AND d.input_key = concat(JSONExtractString(a.metadata, 'manifest_key'), char(0), JSONExtractString(a.metadata, 'live_type'), char(0), JSONExtractString(a.metadata, 'namespace')),
    if(JSONExtractString(d.patch, 'drift') = '',
       toJSONString(mapFilter((key,value) -> key != 'drift', JSONExtract(a.metadata, 'Map(String,String)'))),
       JSONMergePatch(a.metadata, d.patch)), a.metadata) AS metadata
FROM assets AS a
LEFT JOIN (
 SELECT id, max(risk_score) AS risk_score, generation FROM asset_finding_risk
 WHERE id!='' AND (generation,digest) = (SELECT max((generation,digest)) FROM asset_finding_risk WHERE id='' AND pinned=1)
 GROUP BY id,generation
) AS r ON a.id = r.id
LEFT JOIN (
 SELECT id, argMax(input_key, observed_at) AS input_key,
  argMax(patch, observed_at) AS patch, max(observed_at) AS latest_observed_at
 FROM asset_annotations WHERE source = 'k8s_manifest_drift' GROUP BY id
) AS d ON a.id = d.id;

-- Full-table reads retain their existing FINAL semantics.
CREATE VIEW asset_current_with_derivations AS
SELECT a.id AS id,
 a.name AS name,
 a.type AS type,
 a.provider AS provider,
 a.region AS region,
 a.account_id AS account_id,
 a.endpoint AS endpoint,
 a.public_ip AS public_ip,
 a.private_ip AS private_ip,
 a.domain AS domain,
 a.tags AS tags,
 a.discovered_at AS discovered_at,
 a.first_discovered_at AS first_discovered_at,
 a.last_seen AS last_seen,
 a.synced_at AS synced_at,
 greatest(a.risk_score, r.risk_score) AS risk_score,
 if(a.type = 'declared_k8s_workload' AND d.latest_observed_at > toDateTime(0)
    AND d.input_key = concat(JSONExtractString(a.metadata, 'manifest_key'), char(0), JSONExtractString(a.metadata, 'live_type'), char(0), JSONExtractString(a.metadata, 'namespace')),
    if(JSONExtractString(d.patch, 'drift') = '',
       toJSONString(mapFilter((key,value) -> key != 'drift', JSONExtract(a.metadata, 'Map(String,String)'))),
       JSONMergePatch(a.metadata, d.patch)), a.metadata) AS metadata
FROM assets AS a FINAL
LEFT JOIN (
 SELECT id, max(risk_score) AS risk_score, generation FROM asset_finding_risk
 WHERE id!='' AND (generation,digest) = (SELECT max((generation,digest)) FROM asset_finding_risk WHERE id='' AND pinned=1)
 GROUP BY id,generation
) AS r ON a.id = r.id
LEFT JOIN (
 SELECT id, argMax(input_key, observed_at) AS input_key,
  argMax(patch, observed_at) AS patch, max(observed_at) AS latest_observed_at
 FROM asset_annotations WHERE source = 'k8s_manifest_drift' GROUP BY id
) AS d ON a.id = d.id;

-- +goose Down
DROP VIEW asset_current_with_derivations;
DROP VIEW asset_versions_with_derivations;
DROP TABLE asset_annotations;
DROP TABLE asset_risk_publications;
DROP TABLE asset_finding_risk;
