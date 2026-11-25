-- +goose Up
-- Agentless VM disk scanning is opt-in per connector. 'off' reads nothing,
-- 'existing_snapshots' reads snapshots that already exist, 'create_snapshots'
-- may also create short-lived tagged snapshots with the dedicated disk-scan
-- role. disk_scan_enabled_by/at record the admin who last enabled it.
ALTER TABLE connectors
    ADD COLUMN IF NOT EXISTS disk_scan_mode       text        NOT NULL DEFAULT 'off'
        CHECK (disk_scan_mode IN ('off', 'existing_snapshots', 'create_snapshots')),
    ADD COLUMN IF NOT EXISTS disk_scan_enabled_by text        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS disk_scan_enabled_at timestamptz;

CREATE TABLE IF NOT EXISTS disk_scan_runs (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    connector_id uuid        NOT NULL REFERENCES connectors (id) ON DELETE CASCADE,
    status       text        NOT NULL
                 CHECK (status IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'not_enabled')),
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    volumes      integer     NOT NULL DEFAULT 0,
    scanned      integer     NOT NULL DEFAULT 0,
    gaps         integer     NOT NULL DEFAULT 0,
    not_enabled  integer     NOT NULL DEFAULT 0,
    err          text        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS disk_scan_runs_connector_started_idx ON disk_scan_runs (connector_id, started_at DESC);

-- One row per volume per run. A volume whose inventory is not known carries a
-- gap and no trustworthy package count: the CHECK keeps an unreadable,
-- encrypted or unsupported disk from ever being stored as a clean result.
CREATE TABLE IF NOT EXISTS disk_scan_volumes (
    run_id              uuid        NOT NULL REFERENCES disk_scan_runs (id) ON DELETE CASCADE,
    asset_id            text        NOT NULL,
    volume_ref          text        NOT NULL,
    boot                boolean     NOT NULL DEFAULT false,
    snapshot_id         text        NOT NULL DEFAULT '',
    snapshot_source     text        NOT NULL DEFAULT ''
                        CHECK (snapshot_source IN ('', 'reused', 'created', 'image_baseline')),
    encrypted           boolean     NOT NULL DEFAULT false,
    inventory_known     boolean     NOT NULL DEFAULT false,
    cve_matchable_known boolean     NOT NULL DEFAULT false,
    gap                 text        NOT NULL DEFAULT ''
                        CHECK (gap IN ('', 'not_enabled', 'no_snapshot_available', 'snapshot_pending', 'encrypted_no_key',
                                       'unsupported_fs', 'unsupported_partition', 'read_error', 'over_cap',
                                       'permission_denied', 'stale')),
    package_count       integer     NOT NULL DEFAULT 0,
    observed_at         timestamptz NOT NULL,
    PRIMARY KEY (run_id, asset_id, volume_ref),
    CHECK (inventory_known = (gap = '')),
    CHECK (cve_matchable_known <= inventory_known)
);

CREATE INDEX IF NOT EXISTS disk_scan_volumes_asset_idx ON disk_scan_volumes (asset_id, boot DESC, observed_at DESC);

-- The sweeper registry. The intent row is written BEFORE any create call, so a
-- crash between create and record leaves a row a sweep can find; snapshot_id is
-- filled in once the provider answers. (run_id, volume_ref) is unique so a
-- retried job finds its intent instead of creating a second snapshot. No
-- foreign keys: the registry must outlive the run and the connector.
CREATE TABLE IF NOT EXISTS disk_scan_snapshots (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id       text        NOT NULL,
    connector_id text        NOT NULL,
    provider     text        NOT NULL,
    region       text        NOT NULL DEFAULT '',
    volume_ref   text        NOT NULL,
    snapshot_id  text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL,
    delete_after timestamptz NOT NULL,
    deleted_at   timestamptz,
    UNIQUE (run_id, volume_ref)
);

CREATE INDEX IF NOT EXISTS disk_scan_snapshots_orphan_idx ON disk_scan_snapshots (delete_after) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS disk_scan_snapshots_snapshot_idx ON disk_scan_snapshots (provider, snapshot_id) WHERE snapshot_id <> '';

-- Scan results keyed by (provider, snapshot_id): the inventory digest and the
-- touched block extents let a newer snapshot of the same volume reuse the
-- result when no changed block intersects them. expires_at bounds negative
-- entries such as a permission denial.
CREATE TABLE IF NOT EXISTS disk_scan_cache (
    provider            text        NOT NULL,
    snapshot_id         text        NOT NULL,
    digest              text        NOT NULL DEFAULT '',
    extents             jsonb       NOT NULL DEFAULT '[]',
    encrypted           boolean     NOT NULL DEFAULT false,
    inventory_known     boolean     NOT NULL DEFAULT false,
    cve_matchable_known boolean     NOT NULL DEFAULT false,
    gap                 text        NOT NULL DEFAULT ''
                        CHECK (gap IN ('', 'not_enabled', 'no_snapshot_available', 'snapshot_pending', 'encrypted_no_key',
                                       'unsupported_fs', 'unsupported_partition', 'read_error', 'over_cap',
                                       'permission_denied', 'stale')),
    package_count       integer     NOT NULL DEFAULT 0,
    cached_at           timestamptz NOT NULL,
    expires_at          timestamptz,
    PRIMARY KEY (provider, snapshot_id),
    CHECK (inventory_known = (gap = '')),
    CHECK (cve_matchable_known <= inventory_known)
);

-- +goose Down
DROP TABLE IF EXISTS disk_scan_cache;
DROP TABLE IF EXISTS disk_scan_snapshots;
DROP TABLE IF EXISTS disk_scan_volumes;
DROP TABLE IF EXISTS disk_scan_runs;
ALTER TABLE connectors
    DROP COLUMN IF EXISTS disk_scan_enabled_at,
    DROP COLUMN IF EXISTS disk_scan_enabled_by,
    DROP COLUMN IF EXISTS disk_scan_mode;
