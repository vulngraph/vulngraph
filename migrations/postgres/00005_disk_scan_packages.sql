-- +goose Up
-- The package list a disk scan read, latest per (asset, volume). The scanner
-- pod writes it and has no write path to ClickHouse, so the worker's sync
-- overlay turns it into package assets and runs_package edges on every sweep
-- (internal/jobs/sync_diskscan.go). snapshot_id says which snapshot the list
-- was read from: a result is applied only with the list of its own snapshot.
CREATE TABLE IF NOT EXISTS disk_scan_packages (
    asset_id    text        NOT NULL,
    volume_ref  text        NOT NULL,
    run_id      text        NOT NULL,
    snapshot_id text        NOT NULL,
    ecosystem   text        NOT NULL,
    packages    jsonb       NOT NULL,
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (asset_id, volume_ref)
);

-- The scanner pod's whole view of a connector: whether disk scanning is still
-- on. The view runs with its owner's rights, so the scanner role is granted
-- this view and nothing on connectors, whose config column holds every
-- credential.
CREATE VIEW disk_scan_connector_modes AS
SELECT id AS connector_id, disk_scan_mode FROM connectors;

-- +goose Down
DROP VIEW IF EXISTS disk_scan_connector_modes;
DROP TABLE IF EXISTS disk_scan_packages;
