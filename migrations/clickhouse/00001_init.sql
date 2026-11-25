-- +goose Up
-- The Vulngraph ClickHouse schema. Every table lives in the database the
-- CLICKHOUSE_URL names. Every table is ReplacingMergeTree with a TTL, except
-- the append-only audit logs (plain MergeTree, 7-year TTL).

-- Inventory. ORDER BY (type, id): the ReplacingMergeTree dedupe key is the
-- whole sort tuple, so it must not include a column an asset can change
-- (provider does change, for a package seen both in an image and in an SBOM);
-- type is a property of the id and keeps primary-key pruning for type-filtered
-- reads. idx_id serves lookups by id alone. first_discovered_at is the true
-- first observation, carried forward on re-collection; discovered_at is
-- re-stamped by every collector sweep.
CREATE TABLE assets (
    id                  String,
    name                String,
    type                LowCardinality(String),
    provider            LowCardinality(String),
    region              LowCardinality(String),
    account_id          String,
    endpoint            String,
    public_ip           String,
    private_ip          String,
    domain              String,
    tags                Map(String, String),
    metadata            String,
    risk_score          UInt8,
    discovered_at       DateTime,
    last_seen           DateTime,
    synced_at           DateTime,
    first_discovered_at DateTime DEFAULT discovered_at,
    INDEX idx_id id TYPE bloom_filter GRANULARITY 1
)
ENGINE = ReplacingMergeTree(synced_at)
ORDER BY (type, id)
TTL last_seen + INTERVAL 180 DAY;

-- Per-field change history for assets: every changed field with its old and
-- new value. Append-only audit log, never deduplicated.
CREATE TABLE asset_change_log (
    asset_id     String,
    field        LowCardinality(String),  -- e.g. public_ip, name, tag:env, meta:public
    old_value    String,
    new_value    String,
    connector_id String,
    changed_at   DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY (asset_id, changed_at)
TTL changed_at + INTERVAL 7 YEAR;

-- Topology. Live edges are re-stamped every sweep and every reader applies a
-- freshness filter (graphschema.EdgeFreshnessCond), so the 30-day TTL is only
-- a debugging window. dst_id is key position 3, so the primary key cannot prune
-- an incoming-edge lookup; idx_dst_id is what does, at GRANULARITY 1 so a
-- matched entry costs one granule rather than four.
CREATE TABLE graph_edges (
    src_id     String,
    src_type   LowCardinality(String),
    dst_id     String,
    dst_type   LowCardinality(String),
    edge_type  LowCardinality(String),
    properties String,
    synced_at  DateTime,
    INDEX idx_dst_id dst_id TYPE bloom_filter(0.001) GRANULARITY 1
)
ENGINE = ReplacingMergeTree(synced_at)
ORDER BY (src_id, edge_type, dst_id)
TTL synced_at + INTERVAL 30 DAY;

-- Monotonic topology version for the Ladybug incremental sync: the correlate
-- worker writes a higher version after every completed full sweep, and a sync
-- that sees an unchanged version refreshes only finding signals.
CREATE TABLE sync_state (
    key        LowCardinality(String),
    version    UInt64,
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY key
TTL updated_at + INTERVAL 180 DAY;

-- Seed the topology version so reads never return NULL.
INSERT INTO sync_state (key, version) VALUES ('topology_version', 1);

-- Findings. Producers rewrite the whole row on every observation, so
-- enrichment output lives in finding_enrichment. idx_id, idx_resource_id and
-- idx_check_id serve the filters that cannot use the (source, id) key.
--
-- last_observed_at: stamped every time the emitting check re-observes the
--   finding. Not synced_at, which enrich writes also bump.
-- resolved_at: set when the checks ran on the finding's resource and did not
--   re-emit it, or the resource was deleted; zero while open, cleared on
--   regression.
-- resolution_reason: why it stopped being open (finding.ResolutionReason).
-- first_detected_at: the first observation, immutable under re-observation;
--   detected_at is re-stamped on every emission.
CREATE TABLE findings (
    id                String,
    source            LowCardinality(String),
    type              LowCardinality(String),
    severity          LowCardinality(String),
    title             String,
    description       String,
    resource_type     LowCardinality(String),
    resource_id       String,
    resource_name     String,
    region            LowCardinality(String),
    check_id          String,
    template_id       String,
    tags              Map(String, String),
    remediation       String,
    detected_at       DateTime,
    synced_at         DateTime,
    last_observed_at  DateTime DEFAULT 0,
    resolved_at       DateTime DEFAULT 0,
    resolution_reason LowCardinality(String) DEFAULT '',
    first_detected_at DateTime DEFAULT detected_at,
    INDEX idx_resource_id resource_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_id id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_check_id check_id TYPE bloom_filter GRANULARITY 1
)
ENGINE = ReplacingMergeTree(synced_at)
ORDER BY (source, id)
TTL synced_at + INTERVAL 365 DAY;

-- Enrich's output per finding; enrich is this table's only writer. Every read
-- is by finding id, so ORDER BY (id) serves all of them. enriched_at is
-- DateTime64(3) so two writes in one second cannot tie. An open finding
-- re-enriches at least daily, so only a resolved finding's row ages out.
-- owner_* and environment are the routing context (ADR 089); '' is "not yet
-- stamped", distinct from owner_source = 'none' and environment = 'unknown'.
CREATE TABLE finding_enrichment (
    id               String,
    score            UInt8                  DEFAULT 0,
    score_band       LowCardinality(String) DEFAULT '',
    known_exploited  UInt8                  DEFAULT 0,
    dependents       UInt16                 DEFAULT 0,
    unused           UInt8                  DEFAULT 0,
    safety_class     LowCardinality(String) DEFAULT '',
    fix_target       String                 DEFAULT '',
    must_fix_class   LowCardinality(String) DEFAULT '',
    must_fix_reason  String                 DEFAULT '',
    enriched_at      DateTime64(3),
    owner_team       String                 DEFAULT '',
    owner_source     LowCardinality(String) DEFAULT '',
    owner_confidence LowCardinality(String) DEFAULT '',
    environment      LowCardinality(String) DEFAULT ''
)
ENGINE = ReplacingMergeTree(enriched_at)
ORDER BY (id)
TTL toDateTime(enriched_at) + INTERVAL 365 DAY;

CREATE TABLE signals (
    id         String,
    finding_id String,
    asset_id   String,
    source     LowCardinality(String),
    score      UInt8,
    severity   LowCardinality(String),
    factors    String,
    created_at DateTime,
    synced_at  DateTime
)
ENGINE = ReplacingMergeTree(synced_at)
ORDER BY (id)
TTL created_at + INTERVAL 365 DAY;

-- The severity adjudicator's grounded judgments. One row per (finding,
-- provenance), so a deterministic enrich write never shadows the
-- adjudicator's verdict. evidence is a JSON array of cited clauses
-- {clause,source,fact}. input_fingerprint hashes the inputs the belief was
-- formed from, so an unchanged finding is not re-adjudicated. checked_at is
-- when the sweep last confirmed the belief still holds; a re-affirmed belief
-- keeps its created_at, so the TTL is anchored on checked_at.
CREATE TABLE beliefs (
    finding_id        String,
    resource_id       String,
    claim             String,
    severity          LowCardinality(String),
    confidence        LowCardinality(String),
    status            LowCardinality(String),
    provenance        LowCardinality(String),
    evidence          String,
    created_at        DateTime,
    input_fingerprint String DEFAULT '',
    checked_at        DateTime64(3) DEFAULT toDateTime64(created_at, 3)
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (finding_id, provenance)
TTL toDateTime(checked_at) + INTERVAL 90 DAY;

-- The base identity the image-vuln sweep reads off each scanned container
-- image (ADR 088). Its own table because collectors rewrite container_image
-- asset rows whole on every sync. A running digest is re-scanned at least
-- daily, so a 30-day-old row belongs to an image nothing runs.
CREATE TABLE image_bases (
    image_id          String,
    base_image        String,
    base_image_digest String,
    base_image_source LowCardinality(String),
    base_os           LowCardinality(String),
    scanned_at        DateTime64(3)
)
ENGINE = ReplacingMergeTree(scanned_at)
ORDER BY (image_id)
TTL toDateTime(scanned_at) + INTERVAL 30 DAY;

-- Lookalike domains seen in certificate transparency. triage_source is what
-- produced the ai_* verdict (intel.TriageSource): 'llm', 'heuristic' (the
-- similarity/issuer fallback) or '' for no verdict. Every insert writes it; the
-- DEFAULT derives it from ai_reasoning for a row written without it.
CREATE TABLE phishing_candidates (
    id               String,                    -- sha256(domain + monitored_domain) for dedup
    domain           String,                    -- suspected squatting domain
    monitored_domain String,                    -- the domain we were watching
    source           String,                    -- crt_sh | certspotter
    similarity_score Float32,
    issuer           String,
    not_before       DateTime,
    not_after        DateTime,
    status           String  DEFAULT 'pending', -- pending | auto_dismissed | dismissed | confirmed
    ai_confidence    Float32 DEFAULT 0,
    ai_reasoning     String  DEFAULT '',
    detected_at      DateTime,
    confirmed_by     String  DEFAULT '',
    confirmed_at     Nullable(DateTime),
    synced_at        DateTime DEFAULT now(),
    ai_is_phishing   UInt8   DEFAULT 0,
    triage_source    LowCardinality(String) DEFAULT multiIf(
        startsWith(ai_reasoning, 'heuristic'), 'heuristic',
        trimLeft(ai_reasoning) = '' OR startsWith(trimLeft(ai_reasoning), '[auto:'), '',
        'llm')
)
ENGINE = ReplacingMergeTree(synced_at)
ORDER BY (id)
TTL detected_at + INTERVAL 365 DAY;

CREATE TABLE audit_events (
    id          String,
    ts          DateTime,
    actor       String,
    action      LowCardinality(String),
    target_type LowCardinality(String),
    target_id   String,
    details     String
)
ENGINE = MergeTree
ORDER BY (ts, id)
TTL ts + INTERVAL 7 YEAR;

-- +goose Down
DROP TABLE audit_events;
DROP TABLE phishing_candidates;
DROP TABLE image_bases;
DROP TABLE beliefs;
DROP TABLE signals;
DROP TABLE finding_enrichment;
DROP TABLE findings;
DROP TABLE sync_state;
DROP TABLE graph_edges;
DROP TABLE asset_change_log;
DROP TABLE assets;
